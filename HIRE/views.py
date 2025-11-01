from django.shortcuts import render,get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import logout
from django.views.decorators.cache import never_cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from .decorators import login_required_role
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.hashers import make_password, check_password
import os, random
from django.conf import settings
import json
import traceback
from django.http import JsonResponse
from django.http import HttpResponse
from django.utils import timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
from .models import *
from django.utils import timezone
from zoneinfo import ZoneInfo
from django.utils.dateparse import parse_date
from django.db.models import Q
from decimal import Decimal
from .ai_utils import generate_quiz_questions

@never_cache
def index(request):
    return render(request, 'index.html')

@never_cache
def login(request):
    if request.method == "POST":
        role_input = request.POST.get("role")
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            # Get the user by email
            user = TBL_USER.objects.get(EMAIL=email)
        except TBL_USER.DoesNotExist:
            messages.error(request, "User with this email does not exist.")
            return redirect('login')

        # Verify password
        if not check_password(password, user.PASSWORD):
            messages.error(request, "Incorrect password.")
            return redirect('login')

        # Successful login → store user_id in session
        request.session['user_id'] = user.USER_ID

        # --- Capture Login History ---
        ip_address = request.META.get('REMOTE_ADDR', 'Unknown')
        device_info = request.META.get('HTTP_USER_AGENT', 'Unknown')
        local_time = timezone.now().astimezone(ZoneInfo("Asia/Kolkata"))

        TBL_LOGIN_HISTORY.objects.create(
            USER=user,
            LOGIN_TIME=local_time,
            IP_ADDRESS=ip_address,
            DEVICE_INFO=device_info
        )
        # --- End Login History ---

        # Verify role and redirect accordingly
        if role_input == "admin":
            role_obj = TBL_ROLE.objects.get(ROLE_TYPE="Admin")
            if user.ROLE != role_obj:
                messages.error(request, "You are not registered as Admin.")
                return redirect('login')

            admin_profile = TBL_ADMIN.objects.filter(USER=user).first()
            request.session['admin_name'] = admin_profile.ADMIN_NAME if admin_profile else user.USER_NAME
            request.session['role'] = "admin"
            return redirect('adminDashboard')

        elif role_input == "tnp":
            allowed_roles = ["TNP Member", "TNP Head"]
            if user.ROLE.ROLE_TYPE not in allowed_roles:
                messages.error(request, "You are not registered as TNP.")
                return redirect('login')

            tnp_profile = TBL_TNP.objects.filter(USER=user).first()
            request.session['tnp_name'] = tnp_profile.TNP_NAME if tnp_profile else user.USER_NAME
            request.session['role'] = "tnp"
            return redirect('tnpDashboard')

        elif role_input == "company":
            role_obj = TBL_ROLE.objects.get(ROLE_TYPE="Company")
            if user.ROLE != role_obj:
                messages.error(request, "You are not registered as Company.")
                return redirect('login')

            company_profile = TBL_COMPANY.objects.filter(USER=user).first()
            request.session['company_name'] = company_profile.COMPANY_NAME if company_profile else user.USER_NAME
            request.session['role'] = "company"
            return redirect('companyDashboard')
            

        elif role_input == "student":
            role_obj = TBL_ROLE.objects.get(ROLE_TYPE="Student")
            if user.ROLE != role_obj:
                messages.error(request, "You are not registered as Student.")
                return redirect('login')

            student_profile = TBL_STUDENT.objects.filter(USER=user).first()
            request.session['student_name'] = student_profile.STUDENT_NAME if student_profile else user.USER_NAME
            request.session['role'] = "student"
            return redirect('studentDashboard')

        else:
            messages.error(request, "Invalid role selected.")
            return redirect('login')

    return render(request, "login.html")

def forget_password(request):
    """
    Combined single-page Forgot Password + OTP + Reset Password flow
    """
    context = {}

    # Step 2 – Handle OTP + Reset Password
    if 'pending_reset_email' in request.session:
        email = request.session['pending_reset_email']

        if request.method == 'POST':
            otp = request.POST.get('otp')
            password = request.POST.get('password')
            confirm = request.POST.get('confirm_password')

            try:
                user = TBL_USER.objects.get(EMAIL=email)
                record = TBL_EMAIL_VERIFICATION.objects.get(user=user, purpose='reset')

                if record.is_expired():
                    messages.error(request, "OTP expired. Please start again.")
                    del request.session['pending_reset_email']
                    return redirect('forgetPassword')

                if record.otp != otp:
                    messages.error(request, "Invalid OTP. Please try again.")
                    context['show_otp_form'] = True
                    return render(request, 'forget-password.html', context)

                if password != confirm:
                    messages.error(request, "Passwords do not match.")
                    context['show_otp_form'] = True
                    return render(request, 'forget-password.html', context)

                # ✅ Reset password
                user.PASSWORD = make_password(password)
                user.save()
                record.is_verified = True
                record.save()

                del request.session['pending_reset_email']
                messages.success(request, "Password reset successfully! Please login.")
                return redirect('login')

            except (TBL_USER.DoesNotExist, TBL_EMAIL_VERIFICATION.DoesNotExist):
                messages.error(request, "Something went wrong. Try again.")
                return redirect('forgetPassword')

        context['show_otp_form'] = True
        return render(request, 'forget-password.html', context)

    # Step 1 – Send OTP
    if request.method == 'POST':
        email = request.POST.get('email').strip()
        try:
            user = TBL_USER.objects.get(EMAIL=email)
            send_otp_email(user, 'reset')
            request.session['pending_reset_email'] = email
            messages.info(request, f"OTP has been sent to {email}. Please enter it below to reset your password.")
            context['show_otp_form'] = True
            return render(request, 'forget-password.html', context)
        except TBL_USER.DoesNotExist:
            messages.error(request, "No account found with this email.")

    return render(request, 'forget-password.html', context) 

def resend_reset_otp(request):
    email = request.session.get('reset_email')
    if email:
        user = TBL_USER.objects.get(EMAIL=email)
        send_otp_email(user, 'reset')
        messages.info(request, "A new OTP has been sent to your email.")
    return redirect('forgetPassword')

def verify_reset_otp(request, user_id):
    if request.method == "POST":
        otp = request.POST.get('otp')
        try:
            record = TBL_EMAIL_VERIFICATION.objects.get(user_id=user_id, purpose='reset')
            if record.is_expired():
                messages.error(request, "OTP expired. Request a new one.")
            elif record.otp == otp:
                record.is_verified = True
                record.save()
                return redirect('reset_password', user_id=user_id)
            else:
                messages.error(request, "Invalid OTP.")
        except TBL_EMAIL_VERIFICATION.DoesNotExist:
            messages.error(request, "No reset request found.")
    return render(request, 'verify_reset_otp.html', {'user_id': user_id})

@never_cache
def user_logout(request):
    user_id = request.session.get('user_id')
    
    if user_id:
        # Get the most recent login entry for this user
        last_login = TBL_LOGIN_HISTORY.objects.filter(USER_id=user_id).order_by('-LOGIN_TIME').first()
        
        # If a login record exists and no logout time yet, update it
        if last_login and not last_login.LOGOUT_TIME:
            local_time = timezone.now().astimezone(ZoneInfo("Asia/Kolkata"))
            last_login.LOGOUT_TIME = local_time
            last_login.save()

    logout(request)  # Clears the Django session
    request.session.flush()  # Just to ensure all session data is wiped
    
    messages.success(request, "Logged out successfully.")
    return redirect('login')

from HIRE.utils import send_otp_email

from django.core.mail import send_mail
@never_cache
def admin_register(request):
    """
    Unified 3-Step Admin Registration with OTP Verification.
    Step 1: Enter email -> Send OTP
    Step 2: Enter OTP -> Verify
    Step 3: Fill registration form -> Complete registration
    """
    step = request.session.get("admin_step", 1)
    email = request.session.get("admin_email")

    # STEP 1: Send OTP
    if request.method == "POST" and "send_otp" in request.POST:
        admin_email = request.POST.get("admin_email").strip()

        if TBL_USER.objects.filter(EMAIL=admin_email).exists():
            messages.error(request, "Email already registered!")
            return redirect("adminRegister")

        otp = str(random.randint(100000, 999999))
        admin_role, _ = TBL_ROLE.objects.get_or_create(ROLE_TYPE="Admin")

        temp_user = TBL_USER.objects.create(
            USER_NAME="PendingAdmin",
            EMAIL=admin_email,
            PASSWORD="",
            ROLE=admin_role,
            STATUS="Pending",
        )

        TBL_EMAIL_VERIFICATION.objects.create(
            user=temp_user,
            otp=otp,
            purpose="verify",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        send_mail(
            subject="HireVerse - Admin OTP Verification",
            message=f"Your OTP for HireVerse Admin Registration is {otp}. It will expire in 10 minutes.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin_email],
            fail_silently=False,
        )

        request.session["admin_email"] = admin_email
        request.session["admin_step"] = 2
        messages.success(request, f"OTP sent successfully to {admin_email}. Please verify.")
        return redirect("adminRegister")

    # STEP 2: Verify OTP
    if request.method == "POST" and "verify_otp" in request.POST:
        entered_otp = request.POST.get("otp")

        try:
            otp_record = TBL_EMAIL_VERIFICATION.objects.filter(
                user__EMAIL=email, purpose="verify"
            ).latest("created_at")
        except TBL_EMAIL_VERIFICATION.DoesNotExist:
            messages.error(request, "No OTP found. Please request again.")
            return redirect("adminRegister")

        if otp_record.is_expired():
            messages.warning(request, "OTP expired. Please resend.")
            return render(request, "admin-register.html", {"step": 2, "otp_expired": True, "email": email})

        if otp_record.otp != entered_otp:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, "admin-register.html", {"step": 2, "email": email})

        otp_record.is_verified = True
        otp_record.save()

        request.session["admin_step"] = 3
        messages.success(request, "Email verified successfully! Continue registration.")
        return redirect("adminRegister")

    # STEP 3: Complete Registration
    if request.method == "POST" and "register" in request.POST:
        admin_name = request.POST.get('admin_name').strip()
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        admin_phone_no = request.POST.get('admin_phone_no').strip()
        admin_permanent_address = request.POST.get('admin_permanent_address').strip()
        admin_current_address = request.POST.get('admin_current_address').strip()
        admin_profile_photo = request.FILES.get('admin_profile_photo')

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('adminRegister')

        if TBL_ADMIN.objects.filter(ADMIN_PHONE_NO=admin_phone_no).exists():
            messages.error(request, "Phone number already registered!")
            return redirect('adminRegister')

        profile_photo_path = ""
        if admin_profile_photo:
            fs = FileSystemStorage(location="media/profile_photos/")
            filename = fs.save(admin_profile_photo.name, admin_profile_photo)
            profile_photo_path = f"profile_photos/{filename}"

        admin_role = TBL_ROLE.objects.get(ROLE_TYPE="Admin")

        user = TBL_USER.objects.get(EMAIL=email)
        user.USER_NAME = admin_name
        user.PASSWORD = make_password(password)
        user.STATUS = "Active"
        user.save()

        TBL_ADMIN.objects.create(
            ADMIN_NAME=admin_name,
            ROLE_TYPE=admin_role,
            USER=user,
            ADMIN_EMAIL=email,
            ADMIN_PHONE_NO=admin_phone_no,
            ADMIN_PROFILE_PHOTO=profile_photo_path,
            ADMIN_PERMANENT_ADDRESS=admin_permanent_address,
            ADMIN_CURRENT_ADDRESS=admin_current_address,
        )

        for key in ["admin_step", "admin_email"]:
            if key in request.session:
                del request.session[key]

        messages.success(request, "Admin registered successfully! You can now log in.")
        return redirect("login")

    # RESEND OTP
    if request.method == "POST" and "resend_otp" in request.POST:
        otp = str(random.randint(100000, 999999))
        user = TBL_USER.objects.filter(EMAIL=email).first()
        if not user:
            messages.error(request, "Session expired. Please start again.")
            return redirect("adminRegister")

        TBL_EMAIL_VERIFICATION.objects.create(
            user=user,
            otp=otp,
            purpose="verify",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        send_mail(
            subject="HireVerse - Resent OTP",
            message=f"Your new OTP for HireVerse Admin Registration is {otp}. It will expire in 10 minutes.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )

        messages.info(request, f"New OTP sent to {email}.")
        return redirect("adminRegister")

    return render(request, "admin-register.html", {
        "step": step,
        "email": email,
    })

@login_required_role(['admin'])
@never_cache
def admin_dashboard(request):
    # Counts
    total_admins = TBL_USER.objects.filter(ROLE__ROLE_TYPE='Admin').count()
    total_tnp_head = TBL_USER.objects.filter(ROLE__ROLE_TYPE='TNP Head').count()
    total_tnp_member = TBL_USER.objects.filter(ROLE__ROLE_TYPE='TNP Member').count()
    total_companies = TBL_USER.objects.filter(ROLE__ROLE_TYPE='Company').count()
    total_students = TBL_USER.objects.filter(ROLE__ROLE_TYPE='Student').count()
    total_colleges = TBL_COLLEGE.objects.count()

    # ✅ Fetch recent colleges (latest 5 by ID or creation date)
    recent_colleges = TBL_COLLEGE.objects.all().order_by('-COLLEGE_ID')[:5]

    # Optional: Fetch recent reports if needed
    # reports = TBL_REPORT.objects.all().order_by('-REPORT_DATE')[:5] if 'TBL_REPORT' in globals() else []


    context = {
        'total_admins': total_admins,
        'total_tnp': total_tnp_head + total_tnp_member,
        'total_companies': total_companies,
        'total_students': total_students,
        'total_colleges': total_colleges,
        'recent_colleges': recent_colleges,
        # 'reports': reports,
    }

    return render(request, 'admin-dashboard.html', context)

@login_required_role(['admin'])
@never_cache
def add_college(request):
    if request.method == "POST":
        # --- Extract POST Data ---
        college_name = request.POST.get('collegeName', '').strip()
        college_code = request.POST.get('collegeCode', '').strip()
        university = request.POST.get('university', '').strip()
        address = request.POST.get('address', '').strip()
        official_email = request.POST.get('officialEmail', '').strip()
        phone = request.POST.get('phone', '').strip()
        website = request.POST.get('website', '').strip() or None
        year_established = request.POST.get('yearEstablished', '').strip()
        campus_type = request.POST.get('campusType', '').strip()
        status = request.POST.get('status', '').strip()
        campus_size = request.POST.get('campusSize', '').strip() or None
        course_offered = request.POST.get('courseOffered', '').strip() or None
        academic_structure = request.POST.get('academicStructure', '').strip() or None
        notes = request.POST.get('notes', '').strip() or None
        college_logo = request.FILES.get('collegeLogo')

        # --- TNP Head Data ---
        tnp_username = request.POST.get('tnpUserName', '').strip()
        tnp_email = request.POST.get('tnpEmail', '').strip()
        tnp_password = request.POST.get('tnpPassword', '').strip()
        tnp_status = request.POST.get('tnpStatus', '').strip()

        errors = []

        # --- Validate College Data ---
        if not college_name or not college_code or not university or not address:
            errors.append("Please fill all mandatory college fields.")

        # Validate official email
        try:
            validate_email(official_email)
        except ValidationError:
            errors.append("Official Email is invalid.")
        else:
            if TBL_COLLEGE.objects.filter(COLLEGE_EMAIL=official_email).exists():
                errors.append("Official Email already exists for another college.")

        # Validate phone number
        if phone:
            if not phone.isdigit():
                errors.append("Phone number must be numeric.")
            elif TBL_COLLEGE.objects.filter(COLLEGE_PHONE_NO=phone).exists():
                errors.append("Phone number already exists for another college.")

        # Validate year
        if year_established:
            try:
                year_established = int(year_established)
                if year_established < 1800 or year_established > 2100:
                    errors.append("Year Established must be between 1800 and 2100.")
            except ValueError:
                errors.append("Year Established must be a number.")

        # --- Validate TNP User Data ---
        if not tnp_username or not tnp_email or not tnp_password:
            errors.append("Please fill all mandatory TNP fields.")

        # Validate TNP email
        try:
            validate_email(tnp_email)
        except ValidationError:
            errors.append("TNP Email is invalid.")
        else:
            if TBL_USER.objects.filter(EMAIL=tnp_email).exists():
                errors.append("TNP Email already exists.")

        # Validate password length
        if len(tnp_password) < 6:
            errors.append("TNP Password must be at least 6 characters long.")

        # Stop if errors exist
        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect('addCollege')

        # --- Step 1: Create TNP User ---
        role_obj = TBL_ROLE.objects.get(ROLE_TYPE="TNP Head")
        user = TBL_USER.objects.create(
            USER_NAME=tnp_username,
            EMAIL=tnp_email,
            PASSWORD=make_password(tnp_password),
            ROLE=role_obj,
            STATUS=tnp_status
        )

        # --- Step 2: Create College (linked to user) ---
        college = TBL_COLLEGE.objects.create(
            USER=user,
            COLLEGE_NAME=college_name,
            COLLEGE_CODE=college_code,
            COLLEGE_UNIVERSITY=university,
            COLLEGE_ADDRESS=address,
            COLLEGE_EMAIL=official_email,
            COLLEGE_PHONE_NO=phone,
            COLLEGE_WEBSITE_URL=website,
            COLLEGE_ESTABLISHED_YEAR=year_established or None,
            COLLEGE_CAMPUS_TYPE=campus_type,
            COLLEGE_STATUS=status,
            COLLEGE_CAMPUS_SIZE=campus_size,
            COLLEGE_COURSE_OFFERED=course_offered,
            COLLEGE_ACEDEMIC_STRUCTURE=academic_structure,
            COLLEGE_NOTES=notes,
            COLLEGE_LOGO=college_logo
        )

        # --- Step 3: Create TNP Profile ---
        TBL_TNP.objects.create(
            TNP_NAME=tnp_username,
            ROLE_TYPE=role_obj,
            COLLEGE=college,
            USER=user,
            TNP_EMAIL=tnp_email,
        )

        # --- Step 4: Send Email to TNP Head with credentials ---
        try:
            subject = "HireVerse | TNP Head Account Created"
            message = f"""
Dear {tnp_username},

Your college "{college_name}" has been successfully registered in HireVerse.

Here are your login credentials:

Email: {tnp_email}
Password: {tnp_password}

You can log in at: http://127.0.0.1:8000/login/

We recommend changing your password after your first login.

Best Regards,
HireVerse Admin Team
"""
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[tnp_email],
                fail_silently=False,
            )

            messages.success(
                request,
                f'✅ College "{college_name}" and TNP Head "{tnp_username}" added successfully! '
                f'Login credentials have been emailed to {tnp_email}.'
            )

        except Exception as e:
            messages.warning(
                request,
                f"College added successfully, but failed to send email to TNP Head. ({str(e)})"
            )

        return redirect('addCollege')

    return render(request, 'add-College.html')

@login_required_role(['admin'])
@never_cache
def admin_notification(request):
    return render(request, 'admin-notifications.html')

@login_required_role(['admin'])
def college_details(request, college_id):
    try:
        college = TBL_COLLEGE.objects.get(COLLEGE_ID=college_id)
        data = {
            "name": college.COLLEGE_NAME,
            "address": college.COLLEGE_ADDRESS,
            "email": college.COLLEGE_EMAIL,
            "phone": college.COLLEGE_PHONE_NO,
            "university": college.COLLEGE_UNIVERSITY,
            "course": college.COLLEGE_COURSE_OFFERED,
            "established": college.COLLEGE_ESTABLISHED_YEAR,
        }
        return JsonResponse({"success": True, "college": data})
    except TBL_COLLEGE.DoesNotExist:
        return JsonResponse({"success": False, "error": "College not found"})

@login_required_role(['admin'])
@never_cache
def admin_profile(request):
    try:
        # Get logged-in user
        user_id = request.session.get('user_id')  # Assuming you store logged-in user ID in session
        user = TBL_USER.objects.get(pk=user_id)
        admin = TBL_ADMIN.objects.get(USER=user)
    except (TBL_USER.DoesNotExist, TBL_ADMIN.DoesNotExist):
        messages.error(request, "Admin not found!")
        return redirect('login')

    if request.method == "POST":
        if 'full_name' in request.POST:  # Updating personal info
            admin.ADMIN_NAME = request.POST.get('full_name')
            admin.ADMIN_PHONE_NO = request.POST.get('contact_number')
            admin.ADMIN_PERMANENT_ADDRESS = request.POST.get('permanent_address')
            admin.ADMIN_CURRENT_ADDRESS = request.POST.get('current_address')
            
            # Update email in TBL_USER as well
            new_email = request.POST.get('email')
            if new_email != user.EMAIL:
                if TBL_USER.objects.filter(EMAIL=new_email).exclude(pk=user.USER_ID).exists():
                    messages.error(request, "Email already in use by another account!")
                    return redirect('adminProfile')
                user.EMAIL = new_email
                admin.ADMIN_EMAIL = new_email

            # Update full name in TBL_USER
            user.USER_NAME = admin.ADMIN_NAME

            # Handle profile photo
            profile_photo = request.FILES.get('admin_profile_photo')
            if profile_photo:
                fs = FileSystemStorage(location='media/profile_photos/')
                filename = fs.save(profile_photo.name, profile_photo)
                admin.ADMIN_PROFILE_PHOTO = os.path.join('profile_photos', filename)

            user.save()
            admin.save()
            messages.success(request, "Profile updated successfully!")
            return redirect('adminProfile')
    
    if request.method == "POST" and 'old_password' in request.POST:
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not check_password(old_password, user.PASSWORD):
            messages.add_message(request, messages.ERROR, "Old password is incorrect.", extra_tags='password')
        elif new_password != confirm_password:
            messages.add_message(request, messages.ERROR, "New password and confirm password do not match.", extra_tags='password')
        else:
            user.PASSWORD = make_password(new_password)
            user.save()
            messages.add_message(request, messages.SUCCESS, "Password changed successfully!", extra_tags='password')

    # Prepare context to display
    context = {
        'admin': {
            'full_name': admin.ADMIN_NAME,
            'email': admin.ADMIN_EMAIL,
            'role': admin.ROLE_TYPE if admin.ROLE_TYPE else "Admin",
            'contact_number': admin.ADMIN_PHONE_NO,
            'permanent_address': admin.ADMIN_PERMANENT_ADDRESS,
            'current_address': admin.ADMIN_CURRENT_ADDRESS,
            'profile_photo': admin.ADMIN_PROFILE_PHOTO,
        }
    }

    return render(request, 'admin-profile.html', context)

@login_required_role(['admin'])
@never_cache
def admin_view_data(request):
    table_name = request.GET.get('table_name')
    data = []
    headers = []

    table_options_left = ['Roles', 'Users', 'College', 'TNP']
    table_options_right = ['Company', 'Students', 'Login History']

    # Map readable names to Django models
    table_map = {
        "Roles": TBL_ROLE,
        "Users": TBL_USER,
        "College": TBL_COLLEGE,
        "TNP": TBL_TNP,
        "Company": TBL_COMPANY,
        "Students": TBL_STUDENT,
        "Login History": TBL_LOGIN_HISTORY,
    }

    model = None

    if table_name:
        model = table_map.get(table_name)
        if model:
            try:
                queryset = model.objects.all()
                if queryset.exists():
                    headers = [field.name for field in model._meta.fields]

                    # Hide password for Users
                    password_index = None
                    if table_name == "Users" and "PASSWORD" in headers:
                        password_index = headers.index("PASSWORD")
                        headers.pop(password_index)

                    # Build data rows
                    for obj in queryset:
                        row = []
                        for field in model._meta.fields:
                            value = getattr(obj, field.name)
                            if password_index is not None and field.name == "PASSWORD":
                                continue
                            if isinstance(value, models.Model):
                                value = str(value)
                            row.append(value)
                        data.append(row)
            except Exception as e:
                messages.error(request, f"Error fetching data: {str(e)}")
        else:
            messages.warning(request, "Invalid table selected.")

    context = {
        "table_name": table_name,
        "data": data,
        "headers": headers,
        "table_options_left": table_options_left,
        "table_options_right": table_options_right,
        'edit_record_url_exists': True,
        'delete_record_url_exists': True,
    }
    return render(request, "admin-view-data.html", context)


@login_required_role(['admin'])
def edit_record(request, table_name, record_id):
    TABLE_MAP = {
        "Roles": TBL_ROLE,
        "Users": TBL_USER,
        "College": TBL_COLLEGE,
        "TNP": TBL_TNP,
        "Company": TBL_COMPANY,
        "Students": TBL_STUDENT,
        "Login History": TBL_LOGIN_HISTORY,
    }

    model = TABLE_MAP.get(table_name)
    if not model:
        messages.error(request, "Invalid table selected.")
        return redirect("adminViewData")

    record = get_object_or_404(model, pk=record_id)

    if request.method == "POST":
        for field in model._meta.fields:
            field_name = field.name
            if field.primary_key or field.auto_created:
                continue

            # Handle Users password separately
            if table_name == "Users" and field_name == "USER_PASSWORD":
                password = request.POST.get(field_name)
                if password:
                    setattr(record, field_name, password)
                continue

            value = request.POST.get(field_name)
            if value is not None:
                if isinstance(field, models.ForeignKey):
                    try:
                        related_model = field.related_model
                        related_obj = related_model.objects.get(pk=value)
                        setattr(record, field_name, related_obj)
                    except related_model.DoesNotExist:
                        messages.error(request, f"Invalid value for {field_name}.")
                        return redirect("adminViewData")
                else:
                    setattr(record, field_name, value)

        record.save()
        messages.success(request, f"{table_name} record updated successfully!")
        return redirect("adminViewData")

    # Prepare record data for JS (edit card)
    record_data = []
    for field in model._meta.fields:
        if field.primary_key or field.auto_created:
            continue
        value = getattr(record, field.name)
        if isinstance(value, models.Model):
            value = value.pk  # keep foreign key ID for dropdown
        record_data.append(value)

    # Prepare foreign key options for dropdowns
    fk_options = {}
    for field in model._meta.fields:
        if isinstance(field, models.ForeignKey):
            fk_options[field.name] = field.related_model.objects.all()

    return render(request, "admin-view-data.html", {
        "table_name": table_name,
        "record_data": record_data,
        "fk_options": fk_options
    })


@login_required_role(['admin'])
def delete_record(request, table_name, record_id):
    TABLE_MAP = {
        "Roles": TBL_ROLE,
        "Users": TBL_USER,
        "College": TBL_COLLEGE,
        "TNP": TBL_TNP,
        "Company": TBL_COMPANY,
        "Students": TBL_STUDENT,
        "Login History": TBL_LOGIN_HISTORY,
    }

    model = TABLE_MAP.get(table_name)
    if not model:
        messages.error(request, "Invalid table selected.")
        return redirect("adminViewData")

    record = get_object_or_404(model, pk=record_id)

    if request.method == "POST":
        record.delete()
        messages.success(request, f"{table_name} record deleted successfully!")
        return redirect("adminViewData")

    return render(request, "admin-delete-confirmation.html", {
        "table_name": table_name,
        "record_id": record_id,
    })


@login_required_role(['admin'])
@never_cache
def admin_reports(request):
    try:
        colleges = (
            TBL_COLLEGE.objects
            .prefetch_related('tbl_tnp_set', 'tbl_student_set')
            .all()
        )

        data = []
        for c in colleges:
            tnp_count = c.tbl_tnp_set.count()
            student_count = c.tbl_student_set.count()
            data.append({
                "college_name": c.COLLEGE_NAME,
                "college_code": c.COLLEGE_CODE,
                "tnp_count": tnp_count,
                "student_count": student_count,
            })

        context = {"college_data": data}
        return render(request, "admin-reports.html", context)

    except Exception as e:
        print("❌ [Admin Reports Error]:", e)
        messages.error(request, "Error loading reports.")
        return redirect("adminDashboard")

@login_required_role(['tnp'])
@never_cache
def tnp_dashboard(request):
    # 1️⃣ Identify logged-in TNP user
    user_id = request.session.get('user_id')
    tnp_user = TBL_USER.objects.get(pk=user_id)

    try:
        tnp_member = TBL_TNP.objects.get(USER=tnp_user)
        college = tnp_member.COLLEGE  # ForeignKey to TBL_COLLEGE
    except TBL_TNP.DoesNotExist:
        college = None

    # 2️⃣ Total students and recent students
    total_students = TBL_STUDENT.objects.filter(COLLEGE=college).count() if college else 0
    recent_students = (
        TBL_STUDENT.objects.filter(COLLEGE=college).order_by('-STUDENT_ID')[:5]
        if college else []
    )

    # 3️⃣ Jobs related to this college (via companies)
    recent_jobs = (
        TBL_JOB.objects.filter(COMPANY__COLLEGE=college).order_by('-JOB_ID')[:5]
        if college else []
    )
    total_companies = (
        TBL_JOB.objects.filter(COMPANY__COLLEGE=college).values('COMPANY').distinct().count()
        if college else 0
    )

    # 4️⃣ Placed students (based on TBL_APPLICATION)
    placed_students_count = (
        TBL_APPLICATION.objects.filter(
            STUDENT__COLLEGE=college,
            APPLICATION_STATUS='Selected'
        ).values('STUDENT').distinct().count()
        if college else 0
    )

    # 5️⃣ Prepare context for dashboard
    context = {
        'total_students': total_students,
        'total_companies': total_companies,
        'placed_students': placed_students_count,
        'recent_students': recent_students,
        'recent_jobs': recent_jobs,  # renamed for template
    }

    return render(request, 'tnp-dashboard.html', context)

@login_required_role(['tnp'])
def tnp_student_details(request, student_id):
    try:
        student = TBL_STUDENT.objects.get(STUDENT_ID=student_id)
        data = {
            "success": True,
            "student": {
                "STUDENT_NAME": student.STUDENT_NAME,
                "STUDENT_BRANCH": student.STUDENT_BRANCH,
                "STUDENT_EMAIL": student.STUDENT_EMAIL,
                "STUDENT_PHONE_NO": student.STUDENT_PHONE_NO,
                "STUDENT_ENROLLMENT_NUMBER": student.STUDENT_ENROLLMENT_NUMBER,
                "STUDENT_CGPA": student.STUDENT_CGPA,
                "STUDENT_BACKLOG": student.STUDENT_BACKLOG,
                "STUDENT_AREA_OF_INTEREST": student.STUDENT_AREA_OF_INTEREST,
                "STUDENT_LINKEDIN_URL": student.STUDENT_LINKEDIN_URL,
                "STUDENT_GITHUB_LINK": student.STUDENT_GITHUB_LINK,
                "STUDENT_PERSONAL_WEBSITE_PORTFOLIO": student.STUDENT_PERSONAL_WEBSITE_PORTFOLIO,
                "STUDENT_PROFILE_PHOTO": student.STUDENT_PROFILE_PHOTO.url if student.STUDENT_PROFILE_PHOTO else None
            }
        }
    except TBL_STUDENT.DoesNotExist:
        data = {"success": False}
    return JsonResponse(data)

@login_required_role(['tnp'])
def tnp_company_details(request, job_id):
    try:
        job = TBL_JOB.objects.get(JOB_ID=job_id)
        data = {
            "success": True,
            "job": {
                "JOB_TITLE": job.JOB_TITLE,
                "JOB_DESCRIPTION": job.JOB_DESCRIPTION,
                "COMPANY": {"COMPANY_NAME": job.COMPANY.COMPANY_NAME},
                "JOB_LOCATION": job.JOB_LOCATION,
                "JOB_SALARY": job.JOB_SALARY,
                "JOB_TYPE": job.JOB_TYPE,
                "JOB_STATUS": job.JOB_STATUS
            }
        }
    except TBL_JOB.DoesNotExist:
        data = {"success": False}
    return JsonResponse(data)

@login_required_role(['tnp'])
@never_cache
def tnp_add_member(request):
    if request.method == "POST":
        member_type = request.POST.get('member_type')
        errors = []

        # --- Get logged-in user (TNP Head) ---
        user_id = request.session.get('user_id')  # assuming TNP Head's user id is stored in session
        try:
            tnp_head_user = TBL_USER.objects.get(USER_ID=user_id)
            tnp_head_profile = TBL_TNP.objects.get(USER=tnp_head_user)
            user_college = tnp_head_profile.COLLEGE

            # --- DEBUG ---
            print("Logged-in TNP Head User:", tnp_head_user.USER_NAME, tnp_head_user.EMAIL)
            print("TNP Head Profile:", tnp_head_profile.TNP_NAME, tnp_head_profile.TNP_EMAIL)
            print("TNP Head College:", user_college.COLLEGE_NAME, user_college.COLLEGE_CODE)

        except TBL_USER.DoesNotExist:
            messages.error(request, "Logged-in TNP Head not found.")
            return redirect('tnpAddMember')
        except TBL_TNP.DoesNotExist:
            messages.error(request, "TNP Head profile not found.")
            return redirect('tnpAddMember')

        try:
            # -------------------
            # ADD TNP MEMBER
            # -------------------
            if member_type == "tnp":
                full_name = request.POST.get('full_name', '').strip()
                email = request.POST.get('email', '').strip()
                mobile = request.POST.get('mobile', '').strip()
                profile_photo = request.FILES.get('profile_photo')

                # --- DEBUG ---
                print("TNP Member Input:", full_name, email, mobile, profile_photo)

                if not full_name or not email or not mobile:
                    errors.append("Please fill all mandatory fields for TNP.")

                try:
                    validate_email(email)
                except ValidationError:
                    errors.append("Invalid TNP email address.")
                else:
                    if TBL_TNP.objects.filter(TNP_EMAIL=email).exists():
                        errors.append("TNP email already exists.")

                if errors:
                    for e in errors:
                        messages.error(request, e, extra_tags='tnp')
                    return redirect('tnpAddMember')

                # Create User
                role_obj = TBL_ROLE.objects.get(ROLE_TYPE="TNP Member")
                user = TBL_USER.objects.create(
                    USER_NAME=full_name,
                    PASSWORD=make_password('tnp@123'),  # default password
                    EMAIL=email,
                    ROLE=role_obj,
                    STATUS='Active'
                )

                # --- DEBUG ---
                print("Created User for TNP Member:", user.USER_NAME, user.EMAIL, user.ROLE.ROLE_TYPE)

                # Create TNP Profile and inherit college from TNP Head
                tnp_member = TBL_TNP.objects.create(
                    USER=user,
                    TNP_NAME=full_name,
                    TNP_EMAIL=email,
                    TNP_PHONE_NO=mobile,
                    TNP_PROFILE_PHOTO=profile_photo,
                    COLLEGE=user_college,
                    ROLE_TYPE='TNP MEMBER'
                )

                # --- Send Email to TNP Member ---
                try:
                    subject = "HireVerse | TNP Member Account Created"
                    message = f"""
Dear {full_name},

You have been added as a TNP Member in HireVerse by {user_college.COLLEGE_NAME}.

Here are your login credentials:

Email: {email}
Password: tnp@123

You can log in at: http://127.0.0.1:8000/login/

We recommend changing your password after your first login.

Best Regards,
HireVerse Team
"""
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
                except Exception as e:
                    messages.warning(request, f"TNP Member added but email could not be sent: {str(e)}", extra_tags='tnp')

                # --- DEBUG ---
                print("Created TNP Member Profile:", tnp_member.TNP_NAME, tnp_member.TNP_EMAIL,
                      tnp_member.TNP_PHONE_NO, tnp_member.COLLEGE.COLLEGE_NAME)

                messages.success(request, "TNP member added successfully! and E-mail hase sent With Username and Password.", extra_tags='tnp')

            # -------------------
            # ADD COMPANY
            # -------------------
            elif member_type == "company":
                company_name = request.POST.get('company_name', '').strip()
                email = request.POST.get('email', '').strip()
                phone = request.POST.get('phone', '').strip()
                website = request.POST.get('website', '').strip() or None
                industry = request.POST.get('industry', '').strip() or None
                profile_photo = request.FILES.get('profile_photo')

                # --- DEBUG ---
                print("Company Input:", company_name, email, phone, website, industry, profile_photo)

                if not company_name or not email or not phone:
                    errors.append("Please fill all mandatory fields for Company.")

                try:
                    validate_email(email)
                except ValidationError:
                    errors.append("Invalid Company email.")
                else:
                    if TBL_COMPANY.objects.filter(COMPANY_EMAIL=email).exists():
                        errors.append("Company email already exists.")

                if errors:
                    for e in errors:
                        messages.error(request, e, extra_tags='company')
                    return redirect('tnpAddMember')

                role_obj = TBL_ROLE.objects.get(ROLE_TYPE="Company")
                user = TBL_USER.objects.create(
                    USER_NAME=company_name,
                    PASSWORD=make_password('company@123'),
                    EMAIL=email,
                    ROLE=role_obj,
                    STATUS='Active'
                )

                # --- DEBUG ---
                print("Created User for Company:", user.USER_NAME, user.EMAIL, user.ROLE.ROLE_TYPE)

                company = TBL_COMPANY.objects.create(
                    USER=user,
                    COMPANY_NAME=company_name,
                    COMPANY_EMAIL=email,
                    COMPANY_PHONE_NO=phone,
                    COMPANY_WEBSITE=website,
                    COMPANY_INDUSTRY=industry,
                    COLLEGE=user_college,
                    COMPANY_PROFILE_PHOTO=profile_photo
                )

                # --- Send Email to Company ---
                try:
                    subject = "HireVerse | Company Account Created"
                    message = f"""
Dear {company_name},

Your company has been successfully registered with {user_college.COLLEGE_NAME} on HireVerse.

Here are your login credentials:

Email: {email}
Password: company@123

You can log in at: http://127.0.0.1:8000/login/

We recommend changing your password after your first login.

Best Regards,
HireVerse Team
"""
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
                except Exception as e:
                    messages.warning(request, f"Company added but email could not be sent: {str(e)}", extra_tags='company')

                # --- DEBUG ---
                print("Created Company Profile:", company.COMPANY_NAME, company.COMPANY_EMAIL,
                      company.COMPANY_PHONE_NO, company.COLLEGE.COLLEGE_NAME)

                messages.success(request, "Company added successfully! and E-mail hase sent With Username and Password.", extra_tags='company')

            # -------------------
            # ADD STUDENT
            # -------------------
            elif member_type == "student":
                full_name = request.POST.get('full_name', '').strip()
                email = request.POST.get('email', '').strip()
                phone = request.POST.get('phone', '').strip()
                branch = request.POST.get('department', '').strip()
                rollno = request.POST.get('roll_no', '').strip()
                profile_photo = request.FILES.get('profile_photo')

                # --- DEBUG ---
                print("Student Input:", full_name, email, phone, profile_photo)

                if not full_name or not email or not phone or not branch or not rollno:
                    errors.append("Please fill all mandatory fields for Student.")

                try:
                    validate_email(email)
                except ValidationError:
                    errors.append("Invalid Student email.")
                else:
                    if TBL_STUDENT.objects.filter(STUDENT_EMAIL=email).exists():
                        errors.append("Student email already exists.")

                if errors:
                    for e in errors:
                        messages.error(request, e, extra_tags='student')
                    return redirect('tnpAddMember')

                role_obj = TBL_ROLE.objects.get(ROLE_TYPE="Student")
                user = TBL_USER.objects.create(
                    USER_NAME=full_name,
                    PASSWORD=make_password('student@123'),
                    EMAIL=email,
                    ROLE=role_obj,
                    STATUS='Active'
                )

                # --- DEBUG ---
                print("Created User for Student:", user.USER_NAME, user.EMAIL, user.ROLE.ROLE_TYPE)

                student = TBL_STUDENT.objects.create(
                    USER=user,
                    STUDENT_NAME=full_name,
                    STUDENT_EMAIL=email,
                    STUDENT_PHONE_NO=phone,
                    STUDENT_BRANCH=branch,
                    COLLEGE=user_college,
                    STUDENT_ENROLLMENT_NUMBER=rollno,
                    STUDENT_PROFILE_PHOTO=profile_photo,
                    ROLE_TYPE='STUDENT'
                )

                # --- Send Email to Student ---
                try:
                    subject = "HireVerse | Student Account Created"
                    message = f"""
Dear {full_name},

You have been added as a student of {user_college.COLLEGE_NAME} on HireVerse.

Here are your login credentials:

Email: {email}
Password: student@123

You can log in at: http://127.0.0.1:8000/login/

We recommend changing your password after your first login.

Best Regards,
HireVerse Team
"""
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
                except Exception as e:
                    messages.warning(request, f"Student added but email could not be sent: {str(e)}", extra_tags='student')

                # --- DEBUG ---
                print("Created Student Profile:", student.STUDENT_NAME, student.STUDENT_EMAIL,
                      student.STUDENT_PHONE_NO, student.COLLEGE.COLLEGE_NAME)

                messages.success(request, "Student added successfully! and E-mail hase sent With Username and Password.", extra_tags='student')

        except Exception as e:
            messages.error(request, f"Error adding member: {str(e)}", extra_tags=member_type)
            # --- DEBUG ---
            print("Exception occurred:", e)

        return redirect('tnpAddMember')

    return render(request, 'tnp-add-member.html')

@login_required_role(['tnp'])
@never_cache
def tnp_view_data(request):
    try:
        # Retrieve the logged-in user's ID from session
        user_id = request.session.get('user_id')
        if not user_id:
            messages.error(request, "Session expired. Please log in again.")
            return redirect("login")

        # Fetch TBL_USER and related TNP
        user = TBL_USER.objects.get(pk=user_id)
        tnp_profile = TBL_TNP.objects.filter(USER=user).first()

        if not tnp_profile:
            messages.error(request, "TNP profile not found.")
            return redirect("tnpDashboard")

        college = tnp_profile.COLLEGE

    except TBL_USER.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect("login")

    table_name = request.GET.get("table_name")
    data = []
    headers = []

    # Left and right options for the radio form
    table_options_left = ['Students', 'Companies', 'TNP Members']
    table_options_right = ['Login History', 'Jobs', 'Applications']

    # Map readable names to models
    TABLE_MAP = {
        "Students": TBL_STUDENT,
        "Companies": TBL_COMPANY,
        "TNP Members": TBL_TNP,
        "Login History": TBL_LOGIN_HISTORY,
        "Jobs": TBL_JOB,
        "Applications": TBL_APPLICATION,
    }

    model = TABLE_MAP.get(table_name)

    if model:
        try:
            # Filter by same college
            if table_name == "Students":
                queryset = model.objects.filter(COLLEGE=college)

            elif table_name == "Companies":
                queryset = model.objects.filter(COLLEGE=college)

            elif table_name == "TNP Members":
                queryset = model.objects.filter(COLLEGE=college)

            elif table_name == "Jobs":
                queryset = model.objects.filter(COMPANY__COLLEGE=college)

            elif table_name == "Applications":
                queryset = model.objects.filter(STUDENT__COLLEGE=college)

            elif table_name == "Login History":
                # Fetch all login records for users belonging to this college
                college_users = TBL_USER.objects.filter(
                    Q(tbl_student__COLLEGE=college)
                    | Q(tbl_tnp__COLLEGE=college)
                    | Q(tbl_company__COLLEGE=college)
                )
                queryset = model.objects.filter(USER__in=college_users)

            else:
                queryset = model.objects.none()

            if queryset.exists():
                headers = [field.name for field in model._meta.fields]
                for obj in queryset:
                    row = []
                    for field in model._meta.fields:
                        value = getattr(obj, field.name)
                        if isinstance(value, models.Model):
                            value = str(value)
                        row.append(value)
                    data.append(row)
        except Exception as e:
            messages.error(request, f"Error fetching data: {e}")

    context = {
        "college_name": college.COLLEGE_NAME,
        "table_name": table_name,
        "data": data,
        "headers": headers,
        "table_options_left": table_options_left,
        "table_options_right": table_options_right,
    }
    return render(request, "tnp-view-data.html", context)

@login_required_role(['tnp'])
def tnp_edit_record(request, table_name, record_id):
    TABLE_MAP = {
        "Students": TBL_STUDENT,
        "Companies": TBL_COMPANY,
        "TNP Members": TBL_TNP,
        "Jobs": TBL_JOB,
    }

    model = TABLE_MAP.get(table_name)
    if not model:
        messages.error(request, "Invalid table selected.")
        return redirect("tnpViewData")

    record = get_object_or_404(model, pk=record_id)

    if request.method == "POST":
        for field in model._meta.fields:
            if field.primary_key or field.auto_created:
                continue

            value = request.POST.get(field.name)
            if value is not None:
                if isinstance(field, models.ForeignKey):
                    related_obj = field.related_model.objects.get(pk=value)
                    setattr(record, field.name, related_obj)
                else:
                    setattr(record, field.name, value)

        record.save()
        messages.success(request, f"{table_name} record updated successfully!")
        return redirect("tnpViewData")

    return redirect("tnpViewData")

@login_required_role(['tnp'])
def tnp_delete_record(request, table_name, record_id):
    TABLE_MAP = {
        "Students": TBL_STUDENT,
        "Companies": TBL_COMPANY,
        "TNP Members": TBL_TNP,
        "Jobs": TBL_JOB,
    }

    model = TABLE_MAP.get(table_name)
    if not model:
        messages.error(request, "Invalid table selected.")
        return redirect("tnpViewData")

    record = get_object_or_404(model, pk=record_id)

    if request.method == "POST":
        record.delete()
        messages.success(request, f"{table_name} record deleted successfully!")
        return redirect("tnpViewData")

    return redirect("tnpViewData")

@login_required_role(['tnp'])
@never_cache
def tnp_notifications(request):
    return render(request, 'tnp-notifications.html')

@login_required_role(['tnp'])
@never_cache
def tnp_profile(request):
    try:
        # --- Get logged-in user ---
        user_id = request.session.get('user_id')
        user = TBL_USER.objects.get(pk=user_id)

        # --- Get college and TNP profile ---
        college = None
        try:
            college = TBL_COLLEGE.objects.get(USER=user)
        except TBL_COLLEGE.DoesNotExist:
            messages.error(request, "Your college is not registered. Please contact admin.")
            return redirect('tnpProfile')

        tnp, created = TBL_TNP.objects.get_or_create(
            USER=user,
            defaults={
                'TNP_EMAIL': user.EMAIL,
                'TNP_NAME': user.USER_NAME,
                'TNP_PHONE_NO': '',
                'TNP_PERMANENT_ADDRESS': '',
                'TNP_CURRENT_ADDRESS': '',
                'TNP_PROFILE_PHOTO': '',
                'COLLEGE': college
            }
        )

    except TBL_USER.DoesNotExist:
        messages.error(request, "User not found! Please log in again.")
        return redirect('login')

    # ---------- Handle Personal Info Update ----------
    if request.method == "POST" and 'full_name' in request.POST:
        full_name = request.POST.get('full_name')
        contact = request.POST.get('contact')
        permanent = request.POST.get('permanent')
        current = request.POST.get('current')
        email = request.POST.get('email')

        try:
            # Unique field checks for personal info
            if email and email != user.EMAIL:
                if TBL_USER.objects.filter(EMAIL=email).exclude(pk=user.USER_ID).exists() or \
                   TBL_TNP.objects.filter(TNP_EMAIL=email).exclude(USER=user).exists():
                    messages.error(request, "Email is already in use!", extra_tags='personal')
                    return redirect('tnpProfile')

            if contact and contact != tnp.TNP_PHONE_NO:
                if TBL_TNP.objects.filter(TNP_PHONE_NO=contact).exclude(USER=user).exists():
                    messages.error(request, "Phone number is already in use!", extra_tags='personal')
                    return redirect('tnpProfile')

            # Update personal info fields
            if full_name:
                tnp.TNP_NAME = full_name.strip()
                user.USER_NAME = full_name.strip()
            if contact:
                tnp.TNP_PHONE_NO = contact.strip()
            if permanent:
                tnp.TNP_PERMANENT_ADDRESS = permanent.strip()
            if current:
                tnp.TNP_CURRENT_ADDRESS = current.strip()
            if email:
                user.EMAIL = email.strip()
                tnp.TNP_EMAIL = email.strip()

            # Profile photo
            profile_photo = request.FILES.get('TNP_PROFILE_PHOTO')
            if profile_photo:
                fs = FileSystemStorage(location='media/tnp_photos/')
                filename = fs.save(profile_photo.name, profile_photo)
                tnp.TNP_PROFILE_PHOTO = os.path.join('tnp_photos', filename)

            user.save()
            tnp.save()
            messages.success(request, "Personal information updated successfully!", extra_tags='personal')
            return redirect('tnpProfile')

        except Exception as e:
            messages.error(request, f"Error updating personal info: {str(e)}", extra_tags='personal')
            return redirect('tnpProfile')

    # ---------- Handle Social Info Update ----------
    if request.method == "POST" and 'linkedin' in request.POST:
        linkedin = request.POST.get('linkedin')
        github = request.POST.get('github')
        website = request.POST.get('website')

        try:
            # Unique field checks for social info
            if linkedin and linkedin != tnp.TNP_LINKEDIN_URL:
                if TBL_TNP.objects.filter(TNP_LINKEDIN_URL=linkedin).exclude(USER=user).exists():
                    messages.error(request, "LinkedIn URL is already in use!", extra_tags='social')
                    return redirect('tnpProfile')

            if github and github != tnp.TNP_GITHUB_LINK:
                if TBL_TNP.objects.filter(TNP_GITHUB_LINK=github).exclude(USER=user).exists():
                    messages.error(request, "GitHub URL is already in use!", extra_tags='social')
                    return redirect('tnpProfile')

            if website and website != tnp.TNP_PERSONAL_WEBSITE_PORTFOLIO:
                if TBL_TNP.objects.filter(TNP_PERSONAL_WEBSITE_PORTFOLIO=website).exclude(USER=user).exists():
                    messages.error(request, "Website/Portfolio URL is already in use!", extra_tags='social')
                    return redirect('tnpProfile')

            # Update social info
            if linkedin:
                tnp.TNP_LINKEDIN_URL = linkedin.strip()
            if github:
                tnp.TNP_GITHUB_LINK = github.strip()
            if website:
                tnp.TNP_PERSONAL_WEBSITE_PORTFOLIO = website.strip()

            tnp.save()
            messages.success(request, "Social links updated successfully!", extra_tags='social')
            return redirect('tnpProfile')

        except Exception as e:
            messages.error(request, f"Error updating social info: {str(e)}", extra_tags='social')
            return redirect('tnpProfile')

    # ---------- Handle Password Change ----------
    if request.method == "POST" and 'old_password' in request.POST:
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not check_password(old_password, user.PASSWORD):
            messages.error(request, "Old password is incorrect.", extra_tags='password')
        elif new_password != confirm_password:
            messages.error(request, "New password and confirm password do not match.", extra_tags='password')
        else:
            user.PASSWORD = make_password(new_password)
            user.save()
            messages.success(request, "Password changed successfully!", extra_tags='password')
        return redirect('tnpProfile')

    # ---------- Context for template ----------
    context = {
        'tnp': {
            'TNP_NAME': tnp.TNP_NAME or '',
            'TNP_EMAIL': tnp.TNP_EMAIL or user.EMAIL,
            'ROLE': user.ROLE,
            'TNP_PHONE_NO': tnp.TNP_PHONE_NO or '',
            'TNP_PERMANENT_ADDRESS': tnp.TNP_PERMANENT_ADDRESS or '',
            'TNP_CURRENT_ADDRESS': tnp.TNP_CURRENT_ADDRESS or '',
            'COLLEGE': tnp.COLLEGE if tnp.COLLEGE else None,
            'TNP_PROFILE_PHOTO': tnp.TNP_PROFILE_PHOTO,
            'TNP_LINKEDIN_URL': tnp.TNP_LINKEDIN_URL or '',
            'TNP_GITHUB_LINK': tnp.TNP_GITHUB_LINK or '',
            'TNP_PERSONAL_WEBSITE_PORTFOLIO': tnp.TNP_PERSONAL_WEBSITE_PORTFOLIO or '',
            'is_new_profile': created,
        }
    }
    return render(request, 'tnp-profile.html', context)

@login_required_role(['tnp'])
@never_cache
def tnp_reports(request):
    """
    Renders the TNP Reports page.
    Shows aggregate report for each company in the same college.
    Provides company list for dropdown filtering.
    """
    try:
        user_id = request.session.get("user_id")
        tnp = TBL_TNP.objects.select_related("COLLEGE").get(USER_id=user_id)
        college = tnp.COLLEGE

        # Companies under this TNP's college
        companies = (
            TBL_COMPANY.objects
            .filter(COLLEGE=college)
            .prefetch_related('tbl_job_set')
        )

        # Summary report per company
        report_data = []
        for company in companies:
            jobs = company.tbl_job_set.all()
            total_jobs = jobs.count()
            total_applications = TBL_APPLICATION.objects.filter(JOB__in=jobs).count()
            total_selected = TBL_APPLICATION.objects.filter(
                JOB__in=jobs, APPLICATION_STATUS="Selected"
            ).count()

            report_data.append({
                "company": company.COMPANY_NAME,
                "total_jobs": total_jobs,
                "applications": total_applications,
                "selected": total_selected,
            })

        context = {
            "college": college,
            "reports": report_data,
            "companies": companies,  # ✅ Required for dropdown
        }
        return render(request, "tnp-reports.html", context)

    except Exception as e:
        print("❌ [TNP Reports Error]:", e)
        messages.error(request, "Error loading TNP reports.")
        return redirect("tnpDashboard")

# Get all jobs for a selected company
def get_company_jobs(request, company_id):
    try:
        jobs = list(
            TBL_JOB.objects.filter(COMPANY__COMPANY_ID=company_id)
            .values("JOB_ID", "JOB_TITLE")
        )
        return JsonResponse({"jobs": jobs})
    except Exception as e:
        print("❌ [get_company_jobs ERROR]:", e)
        return JsonResponse({"jobs": []})


# Get all placement rounds for a selected job
def get_job_rounds(request, job_id):
    try:
        rounds = list(
            TBL_PLACEMENT_ROUND.objects.filter(JOB__JOB_ID=job_id)
            .values("ROUND_ID", "ROUND_NAME")
        )
        return JsonResponse({"rounds": rounds})
    except Exception as e:
        print("❌ [get_job_rounds ERROR]:", e)
        return JsonResponse({"rounds": []})


# Get all students who passed the selected round (based on logic)
def get_passed_students(request, job_id, round_id):
    try:
        # Fetch job and round details
        job = TBL_JOB.objects.get(JOB_ID=job_id)
        round_obj = TBL_PLACEMENT_ROUND.objects.get(ROUND_ID=round_id)
        round_name = round_obj.ROUND_NAME.strip().lower()

        print(f"🔍 [DEBUG] Getting PASSED students for round: {round_name} | Job: {job.JOB_TITLE}")

        # Fetch all job applications (linked to students)
        all_apps = TBL_APPLICATION.objects.filter(JOB=job).select_related("STUDENT", "STUDENT__USER")

        # Prepare filtered list of passed students
        passed_apps = []

        # --- Logical flow based on round name ---
        if "aptitude" in round_name:
            # All applied students are considered passed for aptitude
            passed_apps = all_apps

        elif "technical" in round_name or "group" in round_name or "gd" in round_name:
            # Passed aptitude (not rejected yet)
            passed_apps = all_apps.exclude(APPLICATION_STATUS="Rejected")

        elif "interview" in round_name and "technical" in round_name:
            # Passed previous technical/GD
            passed_apps = all_apps.filter(APPLICATION_STATUS__in=["Pending", "Selected"])

        elif "hr" in round_name:
            # Only students selected after previous rounds
            passed_apps = all_apps.filter(APPLICATION_STATUS="Selected")

        elif "selected" in round_name or "final" in round_name:
            # Final round — only selected students
            passed_apps = all_apps.filter(APPLICATION_STATUS="Selected")

        else:
            passed_apps = all_apps.none()

        # --- Build list of passed students ---
        students = []
        for app in passed_apps:
            s = app.STUDENT
            u = s.USER
            students.append({
                "name": u.USER_NAME,
                "enrollment": getattr(s, "STUDENT_ENROLLMENT_NUMBER", "N/A"),
                "branch": getattr(s, "STUDENT_BRANCH", "N/A"),
                "status": "Passed",  # ✅ Always show Passed
            })

        print(f"✅ [DEBUG] {len(students)} students PASSED for '{round_name}' (Job: {job.JOB_TITLE})")
        return JsonResponse({"students": students})

    except Exception as e:
        print("❌ [get_passed_students ERROR]:", e)
        return JsonResponse({"students": []})



@login_required_role(['company'])
@never_cache
def company_dashboard(request):
    # 1️⃣ Identify logged-in company user
    user_id = request.session.get('user_id')
    if not user_id:
        return render(request, 'error.html', {"message": "Session expired. Please log in again."})

    try:
        company_user = TBL_USER.objects.get(pk=user_id)
        company = TBL_COMPANY.objects.get(USER=company_user)
    except (TBL_USER.DoesNotExist, TBL_COMPANY.DoesNotExist):
        return render(request, 'error.html', {"message": "Company profile not found."})

    # 2️⃣ Get all jobs posted by this company
    jobs = TBL_JOB.objects.filter(COMPANY=company).order_by('-JOB_ID')
    job_count = jobs.count()

    # 3️⃣ Get all applications related to this company’s jobs
    applications = TBL_APPLICATION.objects.filter(JOB__COMPANY=company)
    application_count = applications.values('STUDENT').distinct().count()

    # 4️⃣ Tests Conducted (based on placement rounds like Aptitude, Technical, HR, etc.)
    test_count = TBL_PLACEMENT_ROUND.objects.filter(COMPANY=company).count()

    # 5️⃣ Placements (applications marked as 'Selected' / 'Placed' / 'Hired')
    placement_count = applications.filter(
        APPLICATION_STATUS__in=['Selected', 'Placed', 'Hired']
    ).values('STUDENT').distinct().count()

    # ✅ Optional: Debug logs (you can keep or remove)
    print(f"🟩 [Dashboard] Jobs={job_count}, Applications={application_count}, Tests={test_count}, Placements={placement_count}")

    # 6️⃣ Prepare context for the template
    context = {
        'company': company,
        'recent_jobs': jobs[:5],  # only show recent 5 jobs
        'applications': applications.select_related('STUDENT', 'JOB')[:5],  # show recent 5 applications
        'job_count': job_count,
        'application_count': application_count,
        'test_count': test_count,
        'placement_count': placement_count,
    }

    return render(request, 'company-dashboard.html', context)



# -----------------------------------------------------
# JOB DETAILS (AJAX for modal)
# -----------------------------------------------------
@login_required_role(['company'])
def company_job_details(request, job_id):
    try:
        job = TBL_JOB.objects.select_related('COMPANY').get(JOB_ID=job_id)
        job_data = {
            "JOB_ID": job.JOB_ID,
            "JOB_TITLE": job.JOB_TITLE,
            "JOB_DESCRIPTION": job.JOB_DESCRIPTION,
            "JOB_SALARY": str(job.JOB_SALARY),
            "JOB_LOCATION": job.JOB_LOCATION,
            "JOB_TYPE": job.JOB_TYPE,
            "JOB_STATUS": job.JOB_STATUS,
            "JOB_POSTED_DATE": job.JOB_POSTED_DATE.strftime("%Y-%m-%d"),
            "COMPANY": {"COMPANY_NAME": job.COMPANY.COMPANY_NAME},
        }
        return JsonResponse({"success": True, "job": job_data})
    except TBL_JOB.DoesNotExist:
        return JsonResponse({"success": False})
    

# Application details view
@login_required_role(['company'])
def company_application_details(request, app_id):
    try:
        app = TBL_APPLICATION.objects.select_related('STUDENT', 'JOB').get(APPLICATION_ID=app_id)
        app_data = {
            "success": True,
            "student": {
                "STUDENT_NAME": app.STUDENT.STUDENT_NAME,
                "STUDENT_EMAIL": app.STUDENT.STUDENT_EMAIL,
                "STUDENT_BRANCH": app.STUDENT.STUDENT_BRANCH,
                "STUDENT_CGPA": str(app.STUDENT.STUDENT_CGPA),
            },
            "job": app.JOB.JOB_TITLE,
            "status": app.APPLICATION_STATUS,
            "application_date": app.APPLICATION_DATE.strftime("%Y-%m-%d"),
        }
        return JsonResponse(app_data)
    except TBL_APPLICATION.DoesNotExist:
        return JsonResponse({"success": False})

@login_required_role(['company'])
@never_cache
def company_job_posts(request):
    # --- Check company login ---
    user_id = request.session.get('user_id')
    if not user_id or request.session.get('role') != 'company':
        messages.error(request, "You must be logged in as a company to access this page.")
        return redirect('login')

    company = TBL_COMPANY.objects.filter(USER_id=user_id).first()
    if not company:
        messages.error(request, "Company profile not found.")
        return redirect('companyDashboard')

    # --- Handle Add/Edit Job POST ---
    if request.method == "POST":
        job_id = request.POST.get("jobId")  # Hidden input for editing
        job_title = request.POST.get("jobTitle")
        job_location = request.POST.get("jobLocation")
        job_type = request.POST.get("jobType")
        job_status = request.POST.get("jobStatus")
        job_description = request.POST.get("jobDescription")
        job_vacancy = request.POST.get("jobVacancy") or 0
        job_salary = request.POST.get("jobSalary") or 0

        if not job_title or not job_location:
            messages.error(request, "Job title and location are required.")
            return redirect('companyJobPosts')

        if job_id:  # Editing
            job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
            job.JOB_TITLE = job_title
            job.JOB_LOCATION = job_location
            job.JOB_TYPE = job_type
            job.JOB_STATUS = job_status
            job.JOB_DESCRIPTION = job_description
            job.JOB_VACANCY = job_vacancy
            job.JOB_SALARY = job_salary
            job.save()
            messages.success(request, f"Job '{job_title}' updated successfully.")
        else:  # Adding
            TBL_JOB.objects.create(
                COMPANY=company,
                JOB_TITLE=job_title,
                JOB_LOCATION=job_location,
                JOB_TYPE=job_type,
                JOB_STATUS=job_status,
                JOB_DESCRIPTION=job_description,
                JOB_VACANCY=job_vacancy,
                JOB_SALARY=job_salary,
                JOB_POSTED_DATE=timezone.now()
            )

            messages.success(request, f"Job '{job_title}' added successfully.")

        return redirect('companyJobPosts')

    # --- Fetch all jobs for the company ---
    jobs = TBL_JOB.objects.filter(COMPANY=company).order_by('-JOB_POSTED_DATE')

    # --- Preload applicants for all jobs ---
    applicants_data = {}
    for job in jobs:
        applications = TBL_APPLICATION.objects.filter(JOB=job).select_related('STUDENT')
        applicants_data[job.JOB_ID] = [
            {
                "name": app.STUDENT.STUDENT_NAME,
                "email": app.STUDENT.STUDENT_EMAIL,
                "status": app.APPLICATION_STATUS
            }
            for app in applications
        ]

    context = {
        "company": company,
        "jobs": jobs,
        "applicants_data": applicants_data
    }
    return render(request, "company-job-posts.html", context)


# Optional: fetch applicants via AJAX
@login_required_role(['company'])
def get_job_applicants(request, job_id):
    user_id = request.session.get('user_id')
    if not user_id or request.session.get('role') != 'company':
        return JsonResponse({"error": "Unauthorized"}, status=401)

    company = TBL_COMPANY.objects.filter(USER_id=user_id).first()
    if not company:
        return JsonResponse({"error": "Company not found"}, status=404)

    job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
    applications = TBL_APPLICATION.objects.filter(JOB=job).select_related('STUDENT')

    data = [
        {
            "name": app.STUDENT.STUDENT_NAME,
            "email": app.STUDENT.STUDENT_EMAIL,
            "college": app.STUDENT.COLLEGE.COLLEGE_NAME if app.STUDENT.COLLEGE else "N/A",
            "status": app.APPLICATION_STATUS
        }
        for app in applications
    ]
    return JsonResponse(data, safe=False)

@login_required_role(['company'])
@never_cache
def company_notifications(request):
    return render(request, 'company-notifications.html')

@login_required_role(['company'])
@never_cache
def company_evaluate_test(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired. Please login again.")
            return redirect("login")

        # ✅ Logged-in company
        company = TBL_COMPANY.objects.get(USER_id=user_id)
        print(f"🟩 [DEBUG] Company: {company.COMPANY_NAME}")

        # ✅ All placement rounds created by this company
        rounds = (
            TBL_PLACEMENT_ROUND.objects
            .filter(COMPANY=company)
            .select_related("JOB", "COLLEGE")
            .order_by("ROUND_ID")
        )

        print(f"🟩 [DEBUG] Found {rounds.count()} rounds for {company.COMPANY_NAME}")

        # ✅ Prepare categorized evaluation data
        evaluation_data = {
            "Aptitude": [],
            "Technical": [],
            "Group_Discussion": [],
            "Technical_Interview": [],
            "HR_Interview": [],
        }

        # ✅ Loop through all placement rounds
        for round_obj in rounds:
            round_name = (round_obj.ROUND_NAME or "").lower()
            round_type = (round_obj.ROUND_TYPE or "").lower()

            # ✅ Get all student results for this round
            round_results = (
                TBL_ROUND_RESULT.objects
                .filter(COMPANY=company, ROUND=round_obj)
                .select_related("STUDENT__USER", "STUDENT__COLLEGE", "JOB")
                .order_by("STUDENT__STUDENT_NAME")
            )

            students_data = []
            for result in round_results:
                student_obj = result.STUDENT
                user_obj = getattr(student_obj, "USER", None)
                college_obj = getattr(student_obj, "COLLEGE", None)

                student_name = (
                    getattr(student_obj, "STUDENT_NAME", None)
                    or getattr(user_obj, "USER_NAME", None)
                    or "Unknown Student"
                )
                college_name = getattr(college_obj, "COLLEGE_NAME", "Unknown College")

                if result.REMARKS and "Scored" in result.REMARKS:
                    try:
                        score = result.REMARKS.split(" ")[1]
                    except IndexError:
                        score = "—"
                else:
                    score = "—"

                students_data.append({
                    "student_name": student_name,
                    "college_name": college_name,
                    "score": score,
                    "status": result.RESULT_STATUS or "Pending",
                    "remarks": result.REMARKS or "—",
                })

            # ✅ Categorize round
            if "aptitude" in round_name or "aptitude" in round_type:
                category = "Aptitude"
            elif any(k in round_name for k in ["technical interview", "tech interview", "tech round"]) or \
                 any(k in round_type for k in ["technical", "tech interview", "tech"]):
                category = "Technical_Interview"
            elif any(k in round_name for k in ["hr interview", "hr round", "human resource"]) or "hr" in round_type:
                category = "HR_Interview"
            elif any(k in round_name for k in ["group discussion", "gd"]) or "gd" in round_type:
                category = "Group_Discussion"
            else:
                category = "Technical"

            evaluation_data[category].append({
                "round": {
                    "round_name": round_obj.ROUND_NAME,
                    "job": {"title": round_obj.JOB.JOB_TITLE},
                },
                "students": students_data,
            })

        # ✅ Fetch Group Discussion Data
        gd_groups = (
            TBL_GD_GROUP.objects
            .filter(COMPANY=company)
            .select_related("JOB", "COLLEGE")
            .order_by("GROUP_NUMBER")
        )

        gd_data = []
        for group in gd_groups:
            members = TBL_GD_GROUP_MEMBER.objects.filter(GROUP=group).select_related("STUDENT__COLLEGE")
            students = []
            for m in members:
                student = m.STUDENT
                app = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=group.JOB).first()
                result = TBL_ROUND_RESULT.objects.filter(
                    STUDENT=student,
                    JOB=group.JOB,
                    COMPANY=company,
                    ROUND__ROUND_NAME__icontains="Group Discussion"
                ).first()

                status = "Pending"
                if result and result.RESULT_STATUS:
                    status = result.RESULT_STATUS
                elif app and app.APPLICATION_STATUS:
                    status = app.APPLICATION_STATUS

                students.append({
                    "id": student.STUDENT_ID,
                    "name": student.STUDENT_NAME,
                    "college": student.COLLEGE.COLLEGE_NAME if student.COLLEGE else "N/A",
                    "status": status,
                })

            gd_data.append({
                "group": group,
                "job_title": group.JOB.JOB_TITLE,
                "students": students,
                "schedule": group.SCHEDULE.strftime("%d-%m-%Y %H:%M") if group.SCHEDULE else "Not Scheduled",
            })

        evaluation_data["Group_Discussion"] = gd_data
        print(f"✅ [DEBUG] GD data added for {len(gd_data)} groups.")

        # ✅ Fetch Technical Interview schedule data
        tech_interviews = (
            TBL_INTERVIEW_SCHEDULE.objects
            .filter(COMPANY=company, ROUND__ROUND_NAME__icontains="Technical")
            .select_related("APPLICATION__STUDENT__COLLEGE", "ROUND", "APPLICATION__JOB")
            .order_by("INTERVIEW_DATE")
        )

        tech_round_data = {}

        for interview in tech_interviews:
            application = interview.APPLICATION
            student = application.STUDENT
            job = application.JOB
            round_obj = interview.ROUND

            # ✅ Get application status (what you want)
            app_status = application.APPLICATION_STATUS or "Pending"

            # Group by round + job
            round_key = f"{round_obj.ROUND_NAME}_{job.JOB_TITLE}"
            if round_key not in tech_round_data:
                tech_round_data[round_key] = {
                    "round": {
                        "round_name": round_obj.ROUND_NAME,
                        "job": {"title": job.JOB_TITLE},
                    },
                    "students": []
                }

            tech_round_data[round_key]["students"].append({
                "student_name": student.STUDENT_NAME,
                "college_name": student.COLLEGE.COLLEGE_NAME if student.COLLEGE else "N/A",
                "status": app_status,  # ✅ use APPLICATION_STATUS here
                "interview_date": timezone.localtime(interview.INTERVIEW_DATE).strftime("%d-%m-%Y %H:%M"),
                "interview_mode": interview.INTERVIEW_MODE,
                "interview_link": interview.INTERVIEW_LINK or "—",
            })

        # ✅ Merge into evaluation_data
        evaluation_data["Technical_Interview"] = list(tech_round_data.values())

        print(f"✅ [DEBUG] Loaded {len(evaluation_data['Technical_Interview'])} Technical Interview rounds")

        # ✅ Fetch HR Interview Data
        hr_interviews = (
            TBL_INTERVIEW_SCHEDULE.objects
            .filter(COMPANY=company, ROUND__ROUND_NAME__icontains="HR")
            .select_related("APPLICATION__STUDENT__COLLEGE", "ROUND", "APPLICATION__JOB")
            .order_by("INTERVIEW_DATE")
        )

        hr_round_data = {}

        for interview in hr_interviews:
            application = interview.APPLICATION
            student = application.STUDENT
            job = application.JOB
            round_obj = interview.ROUND

            # ✅ Get Application Status (e.g. "Selected" or "Rejected")
            app_status = application.APPLICATION_STATUS or "Pending"

            # ✅ Fetch remarks and round result if available
            round_result = TBL_ROUND_RESULT.objects.filter(
                STUDENT=student,
                JOB=job,
                COMPANY=company,
                ROUND=round_obj
            ).first()

            remarks = round_result.REMARKS if round_result else "—"

            # Group by round + job
            round_key = f"{round_obj.ROUND_NAME}_{job.JOB_TITLE}"
            if round_key not in hr_round_data:
                hr_round_data[round_key] = {
                    "round": {
                        "round_name": round_obj.ROUND_NAME,
                        "job": {"title": job.JOB_TITLE},
                    },
                    "students": []
                }

            hr_round_data[round_key]["students"].append({
                "student_name": student.STUDENT_NAME,
                "college_name": student.COLLEGE.COLLEGE_NAME if student.COLLEGE else "N/A",
                "status": app_status,
                "remarks": remarks,
                "interview_date": timezone.localtime(interview.INTERVIEW_DATE).strftime("%d-%m-%Y %H:%M"),
                "interview_mode": interview.INTERVIEW_MODE,
                "interview_link": interview.INTERVIEW_LINK or "—",
            })

        evaluation_data["HR_Interview"] = list(hr_round_data.values())
        print(f"✅ [DEBUG] Loaded {len(evaluation_data['HR_Interview'])} HR Interview rounds.")

        # Render the page
        return render(request, "company-evaluate-test.html", {
            "evaluation_data": evaluation_data,
        })

    except Exception as e:
        print("❌ [ERROR in company_evaluate_test]:", str(e))
        messages.error(request, f"Error fetching evaluation data: {e}")
        return redirect("companyDashboard")

@login_required_role(['company'])   
def send_evaluation_emails(passed_students, failed_students, round_name, company, job_title):
    """
    Sends email notifications to:
      - Each passed student (Congrats for next round)
      - Each failed student (Encouragement email)
      - TNP members (Summary of selected students)
    """
    # 🟩 Send to Passed Students
    for s in passed_students:
        try:
            subject = f"Congratulations! You've advanced to the next round at {company.COMPANY_NAME}"
            message = (
                f"Dear {s.STUDENT_NAME},\n\n"
                f"Congratulations! 🎉 You have successfully cleared the {round_name} for the position of '{job_title}' "
                f"at {company.COMPANY_NAME}.\n\n"
                f"Our team will reach out to you soon with details about the next round.\n\n"
                f"Best of luck!\n"
                f"- {company.COMPANY_NAME} Recruitment Team"
            )
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [s.USER.EMAIL])
            print(f"✅ Email sent to passed student: {s.STUDENT_NAME}")
        except Exception as e:
            print(f"⚠️ Failed to send email to {s.STUDENT_NAME}: {e}")

    # 🟥 Send to Failed Students
    for s in failed_students:
        try:
            subject = f"Update on your application at {company.COMPANY_NAME}"
            message = (
                f"Dear {s.STUDENT_NAME},\n\n"
                f"We appreciate your effort and participation in the {round_name} for the position of '{job_title}'. "
                f"Unfortunately, you have not been selected for the next round.\n\n"
                f"Don't lose hope — your skills and effort are valuable, and we encourage you to keep trying. 🌱\n\n"
                f"Best wishes,\n"
                f"- {company.COMPANY_NAME} Recruitment Team"
            )
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [s.USER.EMAIL])
            print(f"✅ Email sent to failed student: {s.STUDENT_NAME}")
        except Exception as e:
            print(f"⚠️ Failed to send email to {s.STUDENT_NAME}: {e}")

    # 📩 Send to TNP Summary
    try:
        tnp_members = TBL_TNP.objects.filter(COLLEGE=company.COLLEGE)
        if tnp_members.exists() and passed_students:
            tnp_emails = [tnp.USER.EMAIL for tnp in tnp_members if hasattr(tnp, "USER") and tnp.USER.EMAIL]
            passed_list = "\n".join([f"- {s.STUDENT_NAME}" for s in passed_students])

            subject = f"List of students selected for next round ({round_name}) - {company.COMPANY_NAME}"
            message = (
                f"Dear TNP Team,\n\n"
                f"Here is the list of students who have been selected for the next round ({round_name}) "
                f"for the job '{job_title}' at {company.COMPANY_NAME}:\n\n"
                f"{passed_list}\n\n"
                f"Regards,\n{company.COMPANY_NAME} Recruitment Team"
            )
            if tnp_emails:
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, tnp_emails)
                print(f"📨 TNP summary email sent to {len(tnp_emails)} recipients.")
    except Exception as e:
        print(f"⚠️ Failed to send TNP summary email: {e}")

def save_aptitude_quiz(request):
    try:
        user_id = request.session.get('user_id')
        if not user_id or request.session.get('role') != 'student':
            messages.error(request, "Please log in as a student.")
            return redirect('login')

        student = TBL_STUDENT.objects.select_related("USER", "COLLEGE").get(USER_id=user_id)
        company_id = request.POST.get("company_id")
        job_id = request.POST.get("job_id")

        company = TBL_COMPANY.objects.get(pk=company_id)
        job = TBL_JOB.objects.get(pk=job_id, COMPANY=company)

        # ✅ Calculate total score
        total_questions = int(request.POST.get("total_questions", 0))
        correct_answers = 0

        for i in range(total_questions):
            q_id = request.POST.get(f"question_{i}_id")
            selected = request.POST.get(f"question_{i}_option")
            question = TBL_QUIZ_QUESTION.objects.get(pk=q_id)
            if selected == question.CORRECT_OPTION:
                correct_answers += 1

        percentage = (correct_answers / total_questions) * 100
        print(f"🟩 {student.STUDENT_NAME} scored {percentage}%")

        # ✅ Decide Pass/Fail
        result_status = "Passed" if percentage >= 50 else "Failed"  # threshold can be adjusted

        # ✅ Save round result
        round_obj = TBL_PLACEMENT_ROUND.objects.filter(
            COMPANY=company, JOB=job, ROUND_TYPE__icontains="Aptitude"
        ).first()

        if round_obj:
            TBL_ROUND_RESULT.objects.update_or_create(
                STUDENT=student,
                JOB=job,
                COMPANY=company,
                ROUND=round_obj,
                defaults={
                    "RESULT_STATUS": result_status,
                    "REMARKS": f"Scored {percentage:.2f}%",
                    "COLLEGE": student.COLLEGE,
                }
            )

        # ✅ Update application table
        app, created = TBL_APPLICATION.objects.get_or_create(STUDENT=student, JOB=job)
        if result_status == "Passed":
            app.APPLICATION_STATUS = "Technical / Group Discussion"
        else:
            app.APPLICATION_STATUS = "Rejected"
        app.save()

        # ✅ EMAIL NOTIFICATION LOGIC
        passed_students = [student] if result_status == "Passed" else []
        failed_students = [student] if result_status == "Failed" else []

        send_evaluation_emails(
            passed_students=passed_students,
            failed_students=failed_students,
            round_name="Aptitude Round",
            company=company,
            job_title=job.JOB_TITLE
        )

        # ✅ Optional: Success message
        if result_status == "Passed":
            messages.success(request, f"Congratulations! You passed the Aptitude Round with {percentage:.1f}%.")
        else:
            messages.error(request, f"Unfortunately, you did not clear the Aptitude Round. You scored {percentage:.1f}%.")

        return redirect('studentDashboard')

    except Exception as e:
        print("❌ [Error in save_aptitude_quiz]:", e)
        messages.error(request, f"Error submitting quiz: {e}")
        return redirect('studentDashboard')


@login_required_role(['company'])
def company_save_aptitude_evaluation(request, job_id):
    """
    ✅ Handles Aptitude Round evaluation.
    Sends results to students (Passed/Failed) + summary to TNP.
    """
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        if request.method != "POST":
            return JsonResponse({"success": False, "error": "Invalid request method."}, status=400)

        data = json.loads(request.body)
        results = data.get("results", {})  # { student_id: "Passed" / "Failed" }

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
        round_obj = TBL_PLACEMENT_ROUND.objects.filter(
            JOB=job, COMPANY=company, ROUND_NAME__icontains="Aptitude"
        ).first()

        if not round_obj:
            return JsonResponse({"success": False, "error": "Aptitude round not found for this job."}, status=404)

        passed_students = []
        failed_students = []

        # 🔁 Loop through all results
        for student_id, status in results.items():
            student = get_object_or_404(TBL_STUDENT, pk=student_id)

            # 🟦 Update Application Status
            app = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).first()
            if app:
                if status == "Passed":
                    app.APPLICATION_STATUS = "Technical / Group Discussion"
                elif status == "Failed":
                    app.APPLICATION_STATUS = "Rejected"
                app.save()

            # 🟦 Update Round Result
            TBL_ROUND_RESULT.objects.update_or_create(
                STUDENT=student,
                JOB=job,
                COMPANY=company,
                ROUND=round_obj,
                defaults={
                    "COLLEGE": student.COLLEGE or company.COLLEGE,
                    "RESULT_STATUS": status,
                    "REMARKS": f"Scored well in Aptitude" if status == "Passed" else "Needs improvement",
                }
            )

            # 🟩 Collect for email sending
            if status == "Passed":
                passed_students.append(student)
            elif status == "Failed":
                failed_students.append(student)

        # 📧 Send emails to students & TNP
        send_evaluation_emails(
            passed_students=passed_students,
            failed_students=failed_students,
            round_name="Aptitude Round",
            company=company,
            job_title=job.JOB_TITLE
        )

        return JsonResponse({"success": True, "message": "Aptitude evaluation saved and emails sent successfully."})

    except Exception as e:
        print("❌ [ERROR in company_save_aptitude_evaluation]:", str(e))
        return JsonResponse({"success": False, "error": str(e)}, status=500)

# ==============================================================
# ✅ Group Discussion Evaluation
# ==============================================================
@login_required_role(['company'])   
def company_save_gd_evaluation(request, job_id, group_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        if request.method != "POST":
            return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)

        data = json.loads(request.body)
        results = data.get("results", {})

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
        group = get_object_or_404(TBL_GD_GROUP, pk=group_id, COMPANY=company)

        # 🟦 Update statuses and results
        for student_id, status in results.items():
            student = get_object_or_404(TBL_STUDENT, pk=student_id)

            app = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).first()
            if app:
                if status == "Passed":
                    app.APPLICATION_STATUS = "Technical Interview"
                elif status == "Failed":
                    app.APPLICATION_STATUS = "Rejected"
                app.save()

            TBL_ROUND_RESULT.objects.filter(
                STUDENT=student,
                JOB=job,
                COMPANY=company,
                ROUND__ROUND_NAME__icontains="Group Discussion"
            ).update(RESULT_STATUS=status)

        # 🟩 Collect and send emails
        passed_students, failed_students = [], []
        for student_id, status in results.items():
            student = get_object_or_404(TBL_STUDENT, pk=student_id)
            if status == "Passed":
                passed_students.append(student)
            elif status == "Failed":
                failed_students.append(student)

        send_evaluation_emails(
            passed_students=passed_students,
            failed_students=failed_students,
            round_name="Group Discussion",
            company=company,
            job_title=job.JOB_TITLE
        )

        return JsonResponse({"success": True, "message": "GD evaluation saved and emails sent successfully."})

    except Exception as e:
        print("❌ [ERROR in company_save_gd_evaluation]:", e)
        return JsonResponse({"success": False, "error": str(e)}, status=500)



# ==============================================================
# ✅ Technical Interview Evaluation
# ==============================================================
@login_required_role(['company'])
def company_save_tech_evaluation(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        if request.method != "POST":
            return JsonResponse({"success": False, "error": "Invalid request method."}, status=400)

        data = json.loads(request.body)
        job_title = data.get("job_title")
        round_name = data.get("round_name")
        results = data.get("results", {})

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, JOB_TITLE=job_title, COMPANY=company)
        round_obj = get_object_or_404(TBL_PLACEMENT_ROUND, JOB=job, COMPANY=company, ROUND_NAME=round_name)

        # 🟦 Update statuses and results
        for student_key, status in results.items():
            student = TBL_STUDENT.objects.filter(STUDENT_NAME__iexact=student_key.replace("-", " ")).first()
            if not student:
                continue

            TBL_ROUND_RESULT.objects.filter(
                STUDENT=student, JOB=job, COMPANY=company, ROUND=round_obj
            ).update(RESULT_STATUS=status)

            app = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).first()
            if app:
                if status == "Passed":
                    app.APPLICATION_STATUS = "HR Interview"
                else:
                    app.APPLICATION_STATUS = "Rejected"
                app.save()

        # 🟩 Send Email Notifications
        passed_students, failed_students = [], []
        for student_key, status in results.items():
            student = TBL_STUDENT.objects.filter(STUDENT_NAME__iexact=student_key.replace("-", " ")).first()
            if not student:
                continue
            if status == "Passed":
                passed_students.append(student)
            elif status == "Failed":
                failed_students.append(student)

        send_evaluation_emails(
            passed_students, failed_students,
            round_name=round_name,
            company=company,
            job_title=job.JOB_TITLE
        )

        return JsonResponse({"success": True, "message": "Technical evaluation saved and emails sent successfully."})

    except Exception as e:
        print("❌ [ERROR in company_save_tech_evaluation]:", str(e))
        return JsonResponse({"success": False, "error": str(e)}, status=500)



# ==============================================================
# ✅ HR Interview Evaluation
# ==============================================================
@login_required_role(['company'])
def company_save_hr_evaluation(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        if request.method != "POST":
            return JsonResponse({"success": False, "error": "Invalid request method."}, status=400)

        data = json.loads(request.body)
        job_title = data.get("job_title")
        round_name = data.get("round_name")
        results = data.get("results", {})

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, JOB_TITLE=job_title, COMPANY=company)
        round_obj = get_object_or_404(TBL_PLACEMENT_ROUND, JOB=job, COMPANY=company, ROUND_NAME=round_name)

        # 🟦 Save HR results
        for student_key, details in results.items():
            status = details.get("status")
            remarks = details.get("remarks", "")
            student = TBL_STUDENT.objects.filter(STUDENT_NAME__iexact=student_key.replace("-", " ")).first()
            if not student:
                continue

            TBL_ROUND_RESULT.objects.update_or_create(
                STUDENT=student,
                JOB=job,
                COMPANY=company,
                ROUND=round_obj,
                defaults={
                    "COLLEGE": student.COLLEGE or company.COLLEGE,
                    "RESULT_STATUS": status,
                    "REMARKS": remarks,
                }
            )

            app = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).first()
            if app:
                if status == "Passed":
                    app.APPLICATION_STATUS = "Selected"
                elif status == "Failed":
                    app.APPLICATION_STATUS = "Rejected"
                app.save()

        # 🟩 Send Email Notifications
        passed_students, failed_students = [], []
        for student_key, details in results.items():
            status = details.get("status")
            student = TBL_STUDENT.objects.filter(STUDENT_NAME__iexact=student_key.replace("-", " ")).first()
            if not student:
                continue
            if status == "Passed":
                passed_students.append(student)
            elif status == "Failed":
                failed_students.append(student)

        send_evaluation_emails(
            passed_students, failed_students,
            round_name=round_name,
            company=company,
            job_title=job.JOB_TITLE
        )

        return JsonResponse({"success": True, "message": "HR evaluation saved and emails sent successfully."})

    except Exception as e:
        print("❌ [ERROR in company_save_hr_evaluation]:", str(e))
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@login_required_role(['company'])
@never_cache
def company_profile(request):
    try:
        # --- Get logged-in user ---
        user_id = request.session.get('user_id')
        user = TBL_USER.objects.get(pk=user_id)

        # --- Get or create company profile ---
        company, created = TBL_COMPANY.objects.get_or_create(
            USER=user,
            defaults={
                'COMPANY_NAME': user.USER_NAME,
                'COMPANY_EMAIL': user.EMAIL,
                'COMPANY_PHONE_NO': None,
                'COMPANY_PERMANENT_ADDRESS': '',
                'COMPANY_SECONDARY_ADDRESS': '',
                'COMPANY_WEBSITE': '',
                'COMPANY_LINKEDIN_URL': '',
                'COMPANY_INDUSTRY': '',
                'COMPANY_DATE_OF_ESTABLISHMENT': None,
            }
        )
    except TBL_USER.DoesNotExist:
        messages.error(request, "User not found! Please log in again.")
        return redirect('login')

    # ---------- Handle Personal Info Update ----------
    if request.method == "POST" and 'COMPANY_NAME' in request.POST:
        try:
            # Get form data
            company_name = request.POST.get('COMPANY_NAME')
            email = request.POST.get('COMPANY_EMAIL')
            phone = request.POST.get('COMPANY_PHONE_NO')
            permanent_address = request.POST.get('COMPANY_PERMANENT_ADDRESS')
            secondary_address = request.POST.get('COMPANY_SECONDARY_ADDRESS')
            website = request.POST.get('COMPANY_WEBSITE')
            linkedin = request.POST.get('COMPANY_LINKEDIN_URL')
            industry = request.POST.get('COMPANY_INDUSTRY')
            date_est = request.POST.get('COMPANY_DATE_OF_ESTABLISHMENT')

            # --- Validate unique email & phone ---
            if email and email != company.COMPANY_EMAIL:
                if TBL_COMPANY.objects.filter(COMPANY_EMAIL=email).exclude(USER=user).exists():
                    messages.error(request, "Email is already in use!", extra_tags='personal')
                    return redirect('companyProfile')

            if phone and phone != company.COMPANY_PHONE_NO:
                if TBL_COMPANY.objects.filter(COMPANY_PHONE_NO=phone).exclude(USER=user).exists():
                    messages.error(request, "Phone number already in use!", extra_tags='personal')
                    return redirect('companyProfile')

            # --- Update fields ---
            company.COMPANY_NAME = company_name.strip() if company_name else company.COMPANY_NAME
            company.COMPANY_EMAIL = email.strip() if email else company.COMPANY_EMAIL
            company.COMPANY_PHONE_NO = phone.strip() if phone else company.COMPANY_PHONE_NO
            company.COMPANY_PERMANENT_ADDRESS = permanent_address.strip() if permanent_address else company.COMPANY_PERMANENT_ADDRESS
            company.COMPANY_SECONDARY_ADDRESS = secondary_address.strip() if secondary_address else company.COMPANY_SECONDARY_ADDRESS
            company.COMPANY_WEBSITE = website.strip() if website else company.COMPANY_WEBSITE
            company.COMPANY_LINKEDIN_URL = linkedin.strip() if linkedin else company.COMPANY_LINKEDIN_URL
            company.COMPANY_INDUSTRY = industry.strip() if industry else company.COMPANY_INDUSTRY
            company.COMPANY_DATE_OF_ESTABLISHMENT = date_est if date_est else company.COMPANY_DATE_OF_ESTABLISHMENT

            # --- Profile photo ---
            profile_photo = request.FILES.get('COMPANY_PROFILE_PHOTO')
            if profile_photo:
                fs = FileSystemStorage(location='media/profile_photos/company/')
                filename = fs.save(profile_photo.name, profile_photo)
                company.COMPANY_PROFILE_PHOTO = os.path.join('profile_photos/company', filename)

            # --- Update related user name & email ---
            user.USER_NAME = company.COMPANY_NAME
            user.EMAIL = company.COMPANY_EMAIL

            user.save()
            company.save()

            messages.success(request, "Company profile updated successfully!", extra_tags='personal')
            return redirect('companyProfile')

        except Exception as e:
            messages.error(request, f"Error updating profile: {str(e)}", extra_tags='personal')
            return redirect('companyProfile')

    # ---------- Handle Password Change ----------
    if request.method == "POST" and 'old_password' in request.POST:
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not check_password(old_password, user.PASSWORD):
            messages.error(request, "Old password is incorrect.", extra_tags='password')
        elif new_password != confirm_password:
            messages.error(request, "New password and confirm password do not match.", extra_tags='password')
        else:
            user.PASSWORD = make_password(new_password)
            user.save()
            messages.success(request, "Password changed successfully!", extra_tags='password')

        return redirect('companyProfile')

    # ---------- Context for template ----------
    context = {
        'company': company
    }

    return render(request, 'company-profile.html', context)

@login_required_role(['company'])
@never_cache
def company_reports(request):
    try:
        user_id = request.session.get("user_id")
        company = TBL_COMPANY.objects.get(USER_id=user_id)
        colleges = TBL_COLLEGE.objects.all()

        return render(request, "company-reports.html", {"company": company, "colleges": colleges})

    except Exception as e:
        print("❌ [Company Reports Error]:", e)
        messages.error(request, "Error loading reports.")
        return redirect("companyDashboard")


# --- Get all jobs for a company in a specific college ---
def get_jobs_by_college(request, college_id):
    try:
        jobs = list(
            TBL_JOB.objects.filter(COMPANY__COLLEGE_id=college_id)
            .values("JOB_ID", "JOB_TITLE")
        )
        return JsonResponse({"jobs": jobs})
    except Exception as e:
        print("❌ [get_jobs_by_college ERROR]:", e)
        return JsonResponse({"jobs": []})


# --- Get rounds for a specific job ---
def get_rounds_by_job(request, job_id):
    try:
        rounds = list(
            TBL_PLACEMENT_ROUND.objects.filter(JOB_id=job_id)
            .values("ROUND_ID", "ROUND_NAME")
        )
        return JsonResponse({"rounds": rounds})
    except Exception as e:
        print("❌ [get_rounds_by_job ERROR]:", e)
        return JsonResponse({"rounds": []})


# --- Get passed students for a specific round ---
def get_passed_students_company(request, job_id, round_id):
    try:
        job = TBL_JOB.objects.get(JOB_ID=job_id)
        round_obj = TBL_PLACEMENT_ROUND.objects.get(ROUND_ID=round_id)
        round_name = round_obj.ROUND_NAME.strip().lower()

        apps = TBL_APPLICATION.objects.filter(JOB=job)
        passed = []

        if "aptitude" in round_name:
            passed = apps
        elif "technical" in round_name or "group" in round_name or "gd" in round_name:
            passed = apps.exclude(APPLICATION_STATUS="Rejected")
        elif "interview" in round_name or "hr" in round_name:
            passed = apps.filter(APPLICATION_STATUS__in=["Pending", "Selected"])
        elif "selected" in round_name or "final" in round_name:
            passed = apps.filter(APPLICATION_STATUS="Selected")
        else:
            passed = apps

        students = []
        for app in passed.select_related("STUDENT", "STUDENT__USER"):
            s = app.STUDENT
            u = s.USER
            students.append({
                "name": u.USER_NAME,
                "enrollment": getattr(s, "STUDENT_ENROLLMENT_NUMBER", "N/A"),
                "branch": getattr(s, "STUDENT_BRANCH", "N/A"),
                "status": app.APPLICATION_STATUS,
            })

        return JsonResponse({"students": students})

    except Exception as e:
        print("❌ [get_passed_students_company ERROR]:", e)
        return JsonResponse({"students": []})

@login_required_role(['company'])
@never_cache
def company_selection_test(request):
    try:
        # ✅ Check session-based login (HireVerse logic)
        user_id = request.session.get('user_id')
        role = request.session.get('role')

        if not user_id or role != "company":
            messages.error(request, "Please log in as a Company to access this page.")
            return redirect('login')

        # ✅ Fetch company user and company record
        user = get_object_or_404(TBL_USER, pk=user_id)
        company = TBL_COMPANY.objects.filter(USER=user).first()

        if not company:
            messages.error(request, "Company profile not found.")
            return redirect('login')

        # ✅ Fetch jobs created by this company
        jobs = TBL_JOB.objects.filter(COMPANY=company).order_by('-JOB_POSTED_DATE')

        # ✅ Fetch existing GD groups for this company (for display)
        gd_groups = (
            TBL_GD_GROUP.objects
            .filter(COMPANY=company)
            .select_related("JOB", "COLLEGE")
            .order_by("JOB__JOB_TITLE", "GROUP_NUMBER")
        )

        group_data = []
        for g in gd_groups:
            members = TBL_GD_GROUP_MEMBER.objects.filter(GROUP=g).select_related("STUDENT")
            student_names = [m.STUDENT.STUDENT_NAME for m in members]
            group_data.append({
                "group": g,
                "students": student_names,
                "college": g.COLLEGE.COLLEGE_NAME if g.COLLEGE else "N/A",
                "schedule": g.SCHEDULE.strftime("%d-%m-%Y %H:%M") if g.SCHEDULE else "Not Scheduled",
            })

        print(f"🟩 [DEBUG] Loaded {len(group_data)} GD groups for {company.COMPANY_NAME}")

        # ✅ Render page with jobs and groups
        return render(request, "company-selection-tests.html", {
            "company": company,
            "jobs": jobs,
            "groups": group_data,
        })

    except Exception as e:
        print("❌ [ERROR in company_selection_test]:", str(e))
        messages.error(request, f"Error loading selection test page: {e}")
        return redirect('companyDashboard')

from datetime import date

@login_required_role(['company'])
@never_cache
def save_aptitude_quiz(request):
    if request.method == "POST":
        try:
            print("🟩 [DEBUG] Received POST request for aptitude quiz saving.")

            # ✅ Step 1: Extract form data
            job_id = request.POST.get("job_id")
            title = request.POST.get("title", "Aptitude Test")
            total_questions = int(request.POST.get("total_questions", 0))
            pass_marks = int(request.POST.get("pass_marks", 1))
            duration = int(request.POST.get("duration", 30))
            start_date = request.POST.get("start_date")
            end_date = request.POST.get("end_date")

            print(f"🟨 job_id={job_id}, title={title}, duration={duration}, start={start_date}, end={end_date}")

            # ✅ Step 2: Identify logged-in company and college
            user_id = request.session.get("user_id")
            if not user_id:
                messages.error(request, "User session expired. Please log in again.")
                return redirect("/login/")

            try:
                company = TBL_COMPANY.objects.get(USER_id=user_id)
                college = company.COLLEGE
            except TBL_COMPANY.DoesNotExist:
                messages.error(request, "Company not found.")
                return redirect(request.META.get("HTTP_REFERER", "/"))

            # ✅ Step 3: Validate job
            try:
                job = TBL_JOB.objects.get(JOB_ID=job_id)
            except TBL_JOB.DoesNotExist:
                messages.error(request, "Invalid Job selected.")
                return redirect(request.META.get("HTTP_REFERER", "/"))

            # ✅ Step 4: Prevent duplicate quiz creation for the same job
            existing_quiz = TBL_QUIZ.objects.filter(JOB=job).first()
            if existing_quiz:
                messages.warning(request, "A quiz for this job already exists.")
                return redirect(request.META.get("HTTP_REFERER", "/"))

            # ✅ Step 5: Create Quiz
            quiz = TBL_QUIZ.objects.create(
                JOB=job,
                COMPANY=company,
                COLLEGE=college,
                QUIZ_TITLE=title,
                TOTAL_QUESTIONS=total_questions,
                QUIZ_PASS=pass_marks,
                QUIZ_DURATION=duration,
                QUIZ_START_DATE=parse_date(start_date) if start_date else None,
                QUIZ_END_DATE=parse_date(end_date) if end_date else None,
                QUIZ_DATE=date.today(),
            )
            print(f"🟩 Quiz created successfully: ID={quiz.QUIZ_ID}")

            # ✅ Step 6: Create a Placement Round for this quiz
            TBL_PLACEMENT_ROUND.objects.create(
                JOB=job,
                COMPANY=company,
                COLLEGE=college,
                ROUND_NAME=f"{title}",
                ROUND_DATE=parse_date(start_date) if start_date else date.today(),
                ROUND_DURATION=duration,
                ROUND_TYPE="Aptitude",
                ROUND_DESCRIPTION=f"Aptitude round of {company.COMPANY_NAME} for the job {job.JOB_TITLE}",
            )
            print("🟩 Placement round created successfully.")

            # ✅ Step 7: Save all quiz questions
            for i in range(1, total_questions + 1):
                q_text = request.POST.get(f"question_{i}")
                opt_a = request.POST.get(f"option_{i}_A")
                opt_b = request.POST.get(f"option_{i}_B")
                opt_c = request.POST.get(f"option_{i}_C")
                opt_d = request.POST.get(f"option_{i}_D")
                correct = request.POST.get(f"correct_{i}")

                if all([q_text, opt_a, opt_b, opt_c, opt_d, correct]):
                    TBL_QUIZ_QUESTION.objects.create(
                        QUIZ=quiz,
                        QUESTION_TEXT=q_text,
                        OPTION_A=opt_a,
                        OPTION_B=opt_b,
                        OPTION_C=opt_c,
                        OPTION_D=opt_d,
                        CORRECT_OPTION=correct,
                    )
                    print(f"✅ Question {i} saved successfully.")
                else:
                    print(f"⚠️ Skipped Question {i} due to missing fields.")

            messages.success(request, "Aptitude Quiz & Placement Round saved successfully!")
            return redirect(request.META.get("HTTP_REFERER", "/"))

        except Exception as e:
            print("❌ [DEBUG] Error saving aptitude quiz:", str(e))
            messages.error(request, f"Error saving quiz: {e}")
            return redirect(request.META.get("HTTP_REFERER", "/"))

    else:
        messages.error(request, "Invalid request method.")
        return redirect(request.META.get("HTTP_REFERER", "/"))

@login_required_role(['company'])
@never_cache
def ai_generate_and_save_quiz(request):
    """
    Generates an aptitude quiz using AI (Gemini).
    If AI fails, fallback to local stored questions.
    Saves quiz, placement round, and questions.
    """
    print("🟦 [DEBUG] ai_generate_and_save_quiz() called")

    if request.method != "POST":
        print("🟥 [DEBUG] Invalid request method — only POST allowed")
        return HttpResponse("Invalid request method", status=405)

    try:
        # ✅ Step 1: Extract Form Data
        job_id = request.POST.get("job_id")
        title = request.POST.get("title", "Aptitude Test")
        total_questions = int(request.POST.get("total_questions", 10))
        pass_marks = int(request.POST.get("pass_marks", 5))
        duration = int(request.POST.get("duration", 30))
        start_date = request.POST.get("start_date")
        end_date = request.POST.get("end_date")
        difficulty = request.POST.get("difficulty", "Medium")
        topics = request.POST.get("topics", "")

        print(f"""
        🟩 [DEBUG] Form Data:
        job_id={job_id}
        title={title}
        total_questions={total_questions}
        pass_marks={pass_marks}
        duration={duration}
        start_date={start_date}
        end_date={end_date}
        difficulty={difficulty}
        topics={topics}
        """)

        # ✅ Step 2: Validate Logged-in Company
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired. Please log in again.")
            return redirect("/login/")

        try:
            company = TBL_COMPANY.objects.get(USER_id=user_id)
            college = company.COLLEGE
        except TBL_COMPANY.DoesNotExist:
            messages.error(request, "Company not found.")
            return redirect(request.META.get("HTTP_REFERER", "/"))

        # ✅ Step 3: Validate Job
        try:
            job = TBL_JOB.objects.get(JOB_ID=job_id)
        except TBL_JOB.DoesNotExist:
            messages.error(request, "Invalid Job selected.")
            return redirect(request.META.get("HTTP_REFERER", "/"))

        # ✅ Step 4: Prevent Duplicate Quiz for Same Job
        if TBL_QUIZ.objects.filter(JOB=job).exists():
            messages.warning(request, "A quiz for this job already exists.")
            return redirect(request.META.get("HTTP_REFERER", "/"))

        # ✅ Step 5: Try to Generate Questions via Gemini API
        print("🟦 [DEBUG] Generating questions using AI...")
        ai_questions = []
        MAX_RETRIES = 3
        ai_success = False

        for i in range(total_questions):
            for attempt in range(MAX_RETRIES):
                try:
                    result = generate_quiz_questions(topics, 1, difficulty)
                    if isinstance(result, str):
                        result = json.loads(result)
                    if isinstance(result, list):
                        ai_questions.extend(result)
                    ai_success = True
                    print(f"✅ [AI] Question {i+1} generated.")
                    break
                except Exception as e:
                    print(f"⚠️ [AI Retry {attempt+1}] Failed: {e}")
            else:
                print(f"🟥 [AI] Giving up on Question {i+1} after retries.")

        # ✅ Step 6: Fallback to Local Questions if AI Fails
        if not ai_success or len(ai_questions) < total_questions:
            print("🟨 [FALLBACK] Using local fallback questions...")
            try:
                # ✅ Construct full path safely
                fallback_path = os.path.join(settings.BASE_DIR, "static", "data", "fallback_questions.json")

                if not os.path.exists(fallback_path):
                    print(f"🟥 [ERROR] Fallback file not found at: {fallback_path}")
                    messages.error(request, "Fallback questions file not found.")
                    return redirect(request.META.get("HTTP_REFERER", "/"))

                with open(fallback_path, "r", encoding="utf-8") as f:
                    fallback_questions = json.load(f)

                if not isinstance(fallback_questions, list) or len(fallback_questions) == 0:
                    print("🟥 [ERROR] Fallback file is empty or invalid format.")
                    messages.error(request, "Fallback questions file invalid.")
                    return redirect(request.META.get("HTTP_REFERER", "/"))

                random.shuffle(fallback_questions)
                ai_questions = fallback_questions[:total_questions]
                print(f"✅ [FALLBACK] Loaded {len(ai_questions)} questions from fallback.")

            except Exception as e:
                print("🟥 [ERROR] Failed to load fallback:", e)
                messages.error(request, f"AI and fallback both failed: {e}")
                return redirect(request.META.get("HTTP_REFERER", "/"))

        # ✅ Step 7: Create the Quiz
        quiz = TBL_QUIZ.objects.create(
            JOB=job,
            COMPANY=company,
            COLLEGE=college,
            QUIZ_TITLE=title,
            TOTAL_QUESTIONS=total_questions,
            QUIZ_PASS=pass_marks,
            QUIZ_DURATION=duration,
            QUIZ_START_DATE=parse_date(start_date) if start_date else None,
            QUIZ_END_DATE=parse_date(end_date) if end_date else None,
            QUIZ_DATE=date.today(),
        )
        print(f"🟩 Quiz created successfully: ID={quiz.QUIZ_ID}")

        # ✅ Step 8: Create Placement Round
        TBL_PLACEMENT_ROUND.objects.create(
            JOB=job,
            COMPANY=company,
            COLLEGE=college,
            ROUND_NAME=f"{title}",
            ROUND_DATE=parse_date(start_date) if start_date else date.today(),
            ROUND_DURATION=duration,
            ROUND_TYPE="Aptitude",
            ROUND_DESCRIPTION=f"Aptitude round of {company.COMPANY_NAME} for the job {job.JOB_TITLE}",
        )
        print("🟩 Placement Round created successfully.")

        # ✅ Step 9: Save Quiz Questions (Robust format handling)
        # ✅ Step 9: Save Quiz Questions (Handles malformed AI responses too)
        for idx, q in enumerate(ai_questions, start=1):
            try:
                # Case 1: AI returned structured JSON
                if isinstance(q, dict):
                    question_text = q.get("question", "").strip()
                    options = q.get("options", {})
                    correct = q.get("answer", "").strip()

                    # Handle both dict or list options
                    if isinstance(options, list) and len(options) >= 4:
                        opt_a, opt_b, opt_c, opt_d = options[:4]
                    elif isinstance(options, dict):
                        opt_a = options.get("A", "").strip()
                        opt_b = options.get("B", "").strip()
                        opt_c = options.get("C", "").strip()
                        opt_d = options.get("D", "").strip()
                    else:
                        # Invalid options format
                        opt_a = opt_b = opt_c = opt_d = ""

                # Case 2: AI returned plain string (not JSON)
                elif isinstance(q, str):
                    question_text = q.strip()
                    opt_a = opt_b = opt_c = opt_d = ""
                    correct = ""

                else:
                    print(f"⚠️ [Q{idx}] Unsupported format: {type(q)}")
                    continue

                # ✅ Save even if options are missing (at least question text)
                if not question_text:
                    print(f"⚠️ [Q{idx}] Missing question text, skipping.")
                    continue

                TBL_QUIZ_QUESTION.objects.create(
                    QUIZ=quiz,
                    QUESTION_TEXT=question_text,
                    OPTION_A=opt_a,
                    OPTION_B=opt_b,
                    OPTION_C=opt_c,
                    OPTION_D=opt_d,
                    CORRECT_OPTION=correct,
                )
                print(f"✅ [Q{idx}] Saved successfully.")
            except Exception as e:
                print(f"⚠️ [Q{idx}] Skipped due to error: {e}")

        messages.success(request, "AI Quiz & Placement Round generated successfully!")
        return redirect(request.META.get("HTTP_REFERER", "/"))

    except Exception as e:
        print("❌ [ERROR] Quiz generation failed:", e)
        traceback.print_exc()
        messages.error(request, f"Quiz generation failed: {e}")
        return redirect(request.META.get("HTTP_REFERER", "/"))

@login_required_role(['company'])
@never_cache        
def generate_gd_groups(request):
    try:
        if request.method != "POST":
            messages.error(request, "Invalid request method.")
            return redirect("companySelectionTest")

        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired. Please log in again.")
            return redirect("login")

        company = TBL_COMPANY.objects.get(USER_id=user_id)

        job_id = request.POST.get("job_id")
        group_size = int(request.POST.get("group_size", 3))
        start_date = request.POST.get("start_date")

        if not job_id:
            messages.error(request, "Please select a job.")
            return redirect("companySelectionTest")

        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
        print(f"🟩 [DEBUG] Generating GD for {job.JOB_TITLE} | Company: {company.COMPANY_NAME}")

        # ✅ Create or fetch GD round
        gd_round, _ = TBL_PLACEMENT_ROUND.objects.get_or_create(
            JOB=job,
            COMPANY=company,
            ROUND_NAME="Group Discussion",
            defaults={
                "COLLEGE": company.COLLEGE,
                "ROUND_TYPE": "GD",
                "ROUND_DATE": start_date or timezone.now(),
                "ROUND_DURATION": 30,
            }
        )

        # ✅ Get passed students
        passed_students = (
            TBL_ROUND_RESULT.objects
            .filter(
                JOB=job,
                COMPANY=company,
                RESULT_STATUS="Passed",
                ROUND__ROUND_NAME__icontains="aptitude"
            )
            .select_related("STUDENT", "COLLEGE")
        )

        eligible_students = [
            r.STUDENT for r in passed_students
            if TBL_APPLICATION.objects.filter(
                STUDENT=r.STUDENT, JOB=job, APPLICATION_STATUS="Technical/GD"
            ).exists()
        ]

        if not eligible_students:
            messages.warning(request, "No eligible students found for Group Discussion.")
            return redirect("companySelectionTest")

        # ✅ Delete previous groups for the same job
        TBL_GD_GROUP.objects.filter(JOB=job).delete()
        print(f"🟨 [DEBUG] Old GD groups deleted for {job.JOB_TITLE}")

        # ✅ Shuffle and create new ones
        random.shuffle(eligible_students)
        total_groups = (len(eligible_students) + group_size - 1) // group_size

        schedule_time = timezone.now()
        if start_date:
            try:
                schedule_time = timezone.make_aware(
                    datetime.strptime(start_date, "%Y-%m-%d"),
                    timezone.get_current_timezone()
                )
            except Exception:
                schedule_time = timezone.now()

        for i in range(total_groups):
            group_students = eligible_students[i * group_size:(i + 1) * group_size]

            gd_group = TBL_GD_GROUP.objects.create(
                JOB=job,
                COMPANY=company,
                COLLEGE=company.COLLEGE,
                ROUND=gd_round,
                GROUP_NUMBER=i + 1,
                SCHEDULE=schedule_time,
                STATUS="Pending"
            )

            for student in group_students:
                TBL_GD_GROUP_MEMBER.objects.create(GROUP=gd_group, STUDENT=student)

        messages.success(request, f"{total_groups} groups generated successfully for {job.JOB_TITLE}!")

        # ✅ Return same page with updated group list
        return redirect("companySelectionTest")

    except Exception as e:
        print("❌ [ERROR in generate_gd_groups]:", str(e))
        messages.error(request, f"Error generating groups: {e}")
        return redirect("companySelectionTest")

@login_required_role(['company'])    
def company_view_gd_groups(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired. Please login again.")
            return redirect("login")

        company = TBL_COMPANY.objects.get(USER_id=user_id)

        groups = (
            TBL_GD_GROUP.objects
            .filter(COMPANY=company)
            .select_related("JOB", "COLLEGE")
            .order_by("JOB__JOB_TITLE", "GROUP_NUMBER")
        )

        group_data = []
        for g in groups:
            members = TBL_GD_GROUP_MEMBER.objects.filter(GROUP=g).select_related("STUDENT")
            student_names = [m.STUDENT.STUDENT_NAME for m in members]
            group_data.append({
                "group": g,
                "students": student_names,
                "college": g.COLLEGE.COLLEGE_NAME if g.COLLEGE else "N/A",
                "schedule": g.SCHEDULE.strftime("%d-%m-%Y %H:%M") if g.SCHEDULE else "Not Scheduled",
            })

        return render(request, "company-gd-groups.html", {
            "groups": group_data,
            "company": company
        })

    except Exception as e:
        print("❌ [ERROR in company_view_gd_groups]:", str(e))
        messages.error(request, f"Error loading GD groups: {e}")
        return redirect("companySelectionTest")

@login_required_role(['company'])  
def company_send_gd_link(request, group_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired.")
            return redirect("login")

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        group = TBL_GD_GROUP.objects.get(pk=group_id, COMPANY=company)

        # Generate random meeting link (example)
        random_suffix = f"{group.JOB.JOB_ID}-{group.GROUP_NUMBER}-{int(timezone.now().timestamp())}"
        meeting_link = f"https://meet.hireverse.com/{random_suffix}"
        group.MEETING_LINK = meeting_link
        group.STATUS = "Link Sent"
        group.save()

        # Send emails to group members
        members = TBL_GD_GROUP_MEMBER.objects.filter(GROUP=group).select_related("STUDENT__USER")
        for member in members:
            student_user = member.STUDENT.USER
            # # send_mail(
            # #     subject=f"Group Discussion Schedule - {group.JOB.JOB_TITLE}",
            # #     message=(
            # #         f"Dear {member.STUDENT.STUDENT_NAME},\n\n"
            # #         f"You have been scheduled for the Group Discussion for {group.JOB.JOB_TITLE}.\n"
            # #         f"Schedule: {group.SCHEDULE.strftime('%d %b %Y, %I:%M %p')}\n"
            # #         f"Meeting Link: {meeting_link}\n\n"
            # #         f"Best regards,\n{company.COMPANY_NAME} - HireVerse"
            # #     ),
            #     from_email=settings.DEFAULT_FROM_EMAIL,
            #     recipient_list=[student_user.EMAIL],
            #     fail_silently=True,
            # )

        messages.success(request, f"Meeting link generated and sent to all students in Group {group.GROUP_NUMBER}.")
        return redirect("companySelectionTest")

    except Exception as e:
        print("❌ [ERROR in company_send_gd_link]:", str(e))
        messages.error(request, f"Error sending meeting link: {e}")
        return redirect("companySelectionTest")

@login_required_role(['company'])
def company_update_gd_schedule(request, group_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired.")
            return redirect("login")

        if request.method != "POST":
            messages.error(request, "Invalid request method.")
            return redirect("companySelectionTest")

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        group = get_object_or_404(TBL_GD_GROUP, pk=group_id, COMPANY=company)

        new_schedule = request.POST.get("schedule")
        if not new_schedule:
            messages.error(request, "Please select a valid date and time.")
            return redirect("companySelectionTest")

        # Convert to timezone-aware datetime
        schedule_datetime = datetime.strptime(new_schedule, "%Y-%m-%dT%H:%M")
        schedule_aware = timezone.make_aware(schedule_datetime, timezone.get_current_timezone())

        # Update group
        group.SCHEDULE = schedule_aware
        group.STATUS = "Scheduled"
        group.save()

        messages.success(
            request,
            f"Schedule updated for Group {group.GROUP_NUMBER} ({group.JOB.JOB_TITLE})!"
        )
        return redirect("companySelectionTest")

    except Exception as e:
        print("❌ [ERROR in company_update_gd_schedule]:", str(e))
        messages.error(request, f"Error updating schedule: {e}")
        return redirect("companySelectionTest")

@login_required_role(['company'])  
def company_get_eligible_tech_students(request, job_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)

        # ✅ Get eligible students (GD passed or Technical Interview status)
        passed_students = (
            TBL_ROUND_RESULT.objects
            .filter(
                COMPANY=company,
                JOB=job,
                RESULT_STATUS="Passed",
                ROUND__ROUND_NAME__icontains="Group Discussion"
            )
            .select_related("STUDENT__COLLEGE")
        )

        app_students = (
            TBL_APPLICATION.objects
            .filter(JOB=job, APPLICATION_STATUS__in=["Technical Interview", "GD Passed"])
            .select_related("STUDENT__COLLEGE")
        )

        students_dict = {}
        for r in passed_students:
            s = r.STUDENT
            students_dict[s.STUDENT_ID] = {
                "id": s.STUDENT_ID,
                "name": s.STUDENT_NAME,
                "college": s.COLLEGE.COLLEGE_NAME if s.COLLEGE else "N/A",
                "status": r.RESULT_STATUS,
                "slot": "",
                "link": "",
            }

        for a in app_students:
            s = a.STUDENT
            students_dict.setdefault(s.STUDENT_ID, {
                "id": s.STUDENT_ID,
                "name": s.STUDENT_NAME,
                "college": s.COLLEGE.COLLEGE_NAME if s.COLLEGE else "N/A",
                "status": a.APPLICATION_STATUS,
                "slot": "",
                "link": "",
            })

        # ✅ Fetch already scheduled interviews
        interviews = TBL_INTERVIEW_SCHEDULE.objects.filter(COMPANY=company, APPLICATION__JOB=job)
        for i in interviews:
            sid = i.APPLICATION.STUDENT.STUDENT_ID
            if sid in students_dict:
                students_dict[sid]["slot"] = i.INTERVIEW_DATE.strftime("%Y-%m-%dT%H:%M")
                students_dict[sid]["link"] = i.INTERVIEW_LINK
                students_dict[sid]["status"] = i.INTERVIEW_STATUS

        return JsonResponse({"success": True, "students": list(students_dict.values())})

    except Exception as e:
        print("❌ [ERROR in company_get_eligible_tech_students]:", e)
        return JsonResponse({"success": False, "error": str(e)})
    
@login_required_role(['company'])
def company_save_tech_interview(request, job_id, student_id):
    try:
        if request.method != "POST":
            return JsonResponse({"success": False, "error": "Invalid request method."}, status=400)

        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
        student = get_object_or_404(TBL_STUDENT, pk=student_id)
        application = get_object_or_404(TBL_APPLICATION, STUDENT=student, JOB=job)

        # ✅ Get or create Technical Interview round
        round_obj, _ = TBL_PLACEMENT_ROUND.objects.get_or_create(
            JOB=job,
            COMPANY=company,
            ROUND_TYPE="Technical Interview",
            defaults={
                "COLLEGE": company.COLLEGE,
                "ROUND_NAME": "Technical Interview",
                "ROUND_DATE": timezone.now(),
                "ROUND_DURATION": 30,
            }
        )

        data = json.loads(request.body)
        date_value = data.get("date")

        if not date_value:
            return JsonResponse({"success": False, "error": "Interview date missing."})

        # Convert date to timezone-aware datetime
        interview_date = timezone.make_aware(datetime.strptime(date_value, "%Y-%m-%dT%H:%M"))

        # ✅ Check if interview already exists for this student + round
        existing = TBL_INTERVIEW_SCHEDULE.objects.filter(
            APPLICATION=application,
            ROUND=round_obj,
            COMPANY=company
        ).first()

        if existing:
            return JsonResponse({
                "success": False,
                "error": f"Interview already scheduled on {existing.INTERVIEW_DATE.strftime('%d %b %Y, %I:%M %p')}"
            })

        # ✅ Generate new link
        random_suffix = f"{job_id}-{student_id}-{int(timezone.now().timestamp())}"
        meeting_link = f"https://meet.hireverse.com/{random_suffix}"

        # ✅ Save interview schedule
        TBL_INTERVIEW_SCHEDULE.objects.create(
            APPLICATION=application,
            ROUND=round_obj,
            COMPANY=company,
            COLLEGE=company.COLLEGE,
            INTERVIEW_DATE=interview_date,
            INTERVIEW_MODE="Online",
            INTERVIEW_LINK=meeting_link,
            INTERVIEW_STATUS="Scheduled",
        )

        print(f"✅ [DEBUG] Interview created for {student.STUDENT_NAME} ({job.JOB_TITLE})")
        return JsonResponse({"success": True, "link": meeting_link})

    except Exception as e:
        print("❌ [ERROR in company_save_tech_interview]:", e)
        return JsonResponse({"success": False, "error": str(e)})

@login_required_role(['company'])
def company_get_eligible_hr_students(request, job_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)

        # ✅ Get students who passed Technical Interview
        passed_students = (
            TBL_ROUND_RESULT.objects
            .filter(
                COMPANY=company,
                JOB=job,
                RESULT_STATUS="Passed",
                ROUND__ROUND_NAME__icontains="Technical"
            )
            .select_related("STUDENT__COLLEGE")
        )

        # ✅ Get applications marked as eligible for HR
        app_students = (
            TBL_APPLICATION.objects
            .filter(JOB=job, APPLICATION_STATUS__in=["HR Interview", "Technical Passed"])
            .select_related("STUDENT__COLLEGE")
        )

        students_dict = {}
        for r in passed_students:
            s = r.STUDENT
            students_dict[s.STUDENT_ID] = {
                "id": s.STUDENT_ID,
                "name": s.STUDENT_NAME,
                "college": s.COLLEGE.COLLEGE_NAME if s.COLLEGE else "N/A",
                "status": r.RESULT_STATUS,
                "slot": "",
                "link": "",
            }

        for a in app_students:
            s = a.STUDENT
            students_dict.setdefault(s.STUDENT_ID, {
                "id": s.STUDENT_ID,
                "name": s.STUDENT_NAME,
                "college": s.COLLEGE.COLLEGE_NAME if s.COLLEGE else "N/A",
                "status": a.APPLICATION_STATUS,
                "slot": "",
                "link": "",
            })

        # ✅ Fetch already scheduled HR interviews
        interviews = TBL_INTERVIEW_SCHEDULE.objects.filter(
            COMPANY=company,
            APPLICATION__JOB=job,
            ROUND__ROUND_NAME__icontains="HR"
        )
        for i in interviews:
            sid = i.APPLICATION.STUDENT.STUDENT_ID
            if sid in students_dict:
                students_dict[sid]["slot"] = i.INTERVIEW_DATE.strftime("%Y-%m-%dT%H:%M")
                students_dict[sid]["link"] = i.INTERVIEW_LINK
                students_dict[sid]["status"] = i.INTERVIEW_STATUS

        return JsonResponse({"success": True, "students": list(students_dict.values())})
    except Exception as e:
        print("❌ [ERROR in company_get_eligible_hr_students]:", e)
        return JsonResponse({"success": False, "error": str(e)})

@login_required_role(['company'])
def company_save_hr_interview(request, job_id, student_id):
    try:
        if request.method != "POST":
            return JsonResponse({"success": False, "error": "Invalid request method."}, status=400)

        user_id = request.session.get("user_id")
        if not user_id:
            return JsonResponse({"success": False, "error": "Session expired."}, status=401)

        company = TBL_COMPANY.objects.get(USER_id=user_id)
        job = get_object_or_404(TBL_JOB, pk=job_id, COMPANY=company)
        student = get_object_or_404(TBL_STUDENT, pk=student_id)
        application = get_object_or_404(TBL_APPLICATION, STUDENT=student, JOB=job)

        # ✅ Get or create HR Interview round
        round_obj, _ = TBL_PLACEMENT_ROUND.objects.get_or_create(
            JOB=job,
            COMPANY=company,
            ROUND_TYPE="HR Interview",
            defaults={
                "COLLEGE": company.COLLEGE,
                "ROUND_NAME": "HR Interview",
                "ROUND_DATE": timezone.now(),
                "ROUND_DURATION": 30,
            }
        )

        data = json.loads(request.body)
        date_value = data.get("date")
        if not date_value:
            return JsonResponse({"success": False, "error": "Interview date missing."})

        # Convert to timezone-aware datetime
        interview_date = timezone.make_aware(datetime.strptime(date_value, "%Y-%m-%dT%H:%M"))

        # ✅ Prevent double scheduling
        existing = TBL_INTERVIEW_SCHEDULE.objects.filter(
            APPLICATION=application,
            ROUND=round_obj,
            COMPANY=company
        ).first()

        if existing:
            return JsonResponse({
                "success": False,
                "error": f"Interview already scheduled on {existing.INTERVIEW_DATE.strftime('%d %b %Y, %I:%M %p')}"
            })

        # ✅ Generate meeting link
        random_suffix = f"{job_id}-{student_id}-{int(timezone.now().timestamp())}"
        meeting_link = f"https://meet.hireverse.com/{random_suffix}"

        # ✅ Save interview
        TBL_INTERVIEW_SCHEDULE.objects.create(
            APPLICATION=application,
            ROUND=round_obj,
            COMPANY=company,
            COLLEGE=company.COLLEGE,
            INTERVIEW_DATE=interview_date,
            INTERVIEW_MODE="Online",
            INTERVIEW_LINK=meeting_link,
            INTERVIEW_STATUS="Scheduled",
        )

        print(f"✅ [HR] Interview scheduled for {student.STUDENT_NAME} ({job.JOB_TITLE})")
        return JsonResponse({"success": True, "link": meeting_link})

    except Exception as e:
        print("❌ [ERROR in company_save_hr_interview]:", e)
        return JsonResponse({"success": False, "error": str(e)})


@login_required_role(['student'])
@never_cache
def student_dashboard(request):
    try:
        # 1️⃣ Validate session
        user_id = request.session.get('user_id')
        role = request.session.get('role')
        if not user_id or role != "student":
            messages.error(request, "Please log in as a student.")
            return redirect('login')

        # 2️⃣ Fetch student
        student_user = TBL_USER.objects.filter(pk=user_id).first()
        if not student_user:
            messages.error(request, "User not found.")
            return redirect('login')

        student = (
            TBL_STUDENT.objects
            .select_related("USER", "COLLEGE")
            .filter(USER=student_user)
            .first()
        )
        if not student:
            messages.error(request, "Student profile not found.")
            return redirect('login')

        # 3️⃣ Applications
        applications = (
            TBL_APPLICATION.objects
            .filter(STUDENT=student)
            .select_related('JOB', 'JOB__COMPANY')
            .order_by('-APPLICATION_ID')
        )
        application_count = applications.count()

        # 4️⃣ Active Jobs & Companies
        active_jobs_qs = (
            TBL_JOB.objects
            .filter(JOB_STATUS='Open')
            .select_related('COMPANY')
            .order_by('-JOB_ID')
        )
        # ✅ count before slicing
        company_count = active_jobs_qs.values('COMPANY').distinct().count()
        active_jobs = active_jobs_qs[:5]

        # 5️⃣ Tests scheduled
        test_count = (
            TBL_PLACEMENT_ROUND.objects
            .filter(JOB__in=applications.values('JOB'))
            .distinct()
            .count()
        )

        # 6️⃣ Placements
        placement_count = applications.filter(
            APPLICATION_STATUS__in=['Selected', 'Placed', 'Hired']
        ).count()

        # 7️⃣ Reports (optional)
        # reports = []
        # if 'TBL_PLACEMENT_RESULT' in globals():
        #     reports = (
        #         TBL_PLACEMENT_RESULT.objects
        #         .filter(STUDENT=student)
        #         .order_by('-RESULT_ID')[:5]
        #     )

        # ✅ Prepare context
        context = {
            'student': student,
            'applications': applications[:5],
            'companies': active_jobs,
            # 'reports': reports,
            'company_count': company_count,
            'application_count': application_count,
            'test_count': test_count,
            'placement_count': placement_count,
        }

        print(f"🟢 [StudentDashboard] {student.STUDENT_NAME}: Apps={application_count}, Companies={company_count}, Tests={test_count}, Placements={placement_count}")
        return render(request, 'student-dashboard.html', context)

    except Exception as e:
        print("❌ [StudentDashboard Error]:", str(e))
        messages.error(request, f"Error loading dashboard: {e}")
        return redirect('login')

@login_required_role(['student'])
def job_details(request, job_id):
    print(f"🟩 [DEBUG] job_details called with job_id={job_id}")
    try:
        job = TBL_JOB.objects.select_related("COMPANY").get(pk=job_id)
        print(f"✅ Found job: {job.JOB_TITLE} ({job.COMPANY.COMPANY_NAME})")

        data = {
            "success": True,
            "job": {
                "JOB_ID": job.JOB_ID,
                "JOB_TITLE": job.JOB_TITLE,
                "COMPANY": {"COMPANY_NAME": job.COMPANY.COMPANY_NAME},
                "JOB_DESCRIPTION": job.JOB_DESCRIPTION or "No description available.",
                "JOB_LOCATION": job.JOB_LOCATION or "Not specified",
                "JOB_SALARY": str(job.JOB_SALARY),
                "JOB_TYPE": job.JOB_TYPE or "Full Time",
                "JOB_STATUS": job.JOB_STATUS,
                "JOB_POSTED_DATE": str(job.JOB_POSTED_DATE),
            },
        }
        return JsonResponse(data)

    except Exception as e:
        print(f"❌ [ERROR in job_details]: {e}")
        return JsonResponse({"success": False, "error": str(e)})

@login_required_role(['student'])   
def application_details(request, app_id):
    try:
        app = (
            TBL_APPLICATION.objects
            .select_related("STUDENT", "STUDENT__USER", "JOB", "JOB__COMPANY")
            .get(pk=app_id)
        )
        student = app.STUDENT
        user = getattr(student, "USER", None)

        data = {
            "success": True,
            "student": {
                "STUDENT_ID": student.STUDENT_ID,
                "STUDENT_NAME": student.STUDENT_NAME,
                "STUDENT_EMAIL": user.EMAIL if user else "N/A",
                "STUDENT_BRANCH": student.STUDENT_BRANCH or "N/A",
                "STUDENT_CGPA": student.STUDENT_CGPA or "N/A",
            },
            "job": app.JOB.JOB_TITLE,
            "status": app.APPLICATION_STATUS,
            "application_date": format(app.APPLICATION_DATE, "Y-m-d H:i") if app.APPLICATION_DATE else "N/A",
        }
        return JsonResponse(data)

    except TBL_APPLICATION.DoesNotExist:
        return JsonResponse({"success": False, "error": "Application not found"})
    except Exception as e:
        print(f"❌ [application_details Error]: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@login_required_role(['student'])
@never_cache
def student_notifications(request):
    return render(request, 'student-notifications.html')

from django.db import transaction

@login_required_role(['student'])
@never_cache
# ✅ 1. Show Available Tests
def student_test(request):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired. Please login again.")
            return redirect("login")

        student = TBL_STUDENT.objects.get(USER_id=user_id)
        college = student.COLLEGE
        print(f"🟩 [DEBUG] Logged-in Student: {student.STUDENT_NAME}, College: {college.COLLEGE_NAME}")

        # ✅ Jobs the student applied for
        applied_jobs = TBL_APPLICATION.objects.filter(STUDENT=student).values_list("JOB", flat=True)
        print(f"🟩 [DEBUG] Applied Job IDs: {list(applied_jobs)}")

        # ✅ Placement rounds for those jobs
        available_rounds = (
            TBL_PLACEMENT_ROUND.objects
            .filter(JOB__in=applied_jobs)
            .select_related("JOB", "COMPANY", "COLLEGE")
            .order_by("ROUND_DATE")
        )

        # ✅ Completed rounds
        completed_rounds = (
            TBL_ROUND_RESULT.objects
            .filter(STUDENT=student, RESULT_STATUS__in=["Passed", "Failed"])
            .exclude(ROUND__isnull=True)
            .values_list("ROUND__ROUND_ID", flat=True)
        )
        completed_round_ids = set(completed_rounds)
        print(f"🟩 [DEBUG] Completed Round IDs: {completed_round_ids}")

        available_quizzes = []
        now = timezone.localtime(timezone.now())

        for round_obj in available_rounds:
            job = round_obj.JOB
            company = job.COMPANY
            already_attempted = round_obj.ROUND_ID in completed_round_ids

            round_type = (round_obj.ROUND_TYPE or "").strip().lower()
            round_name = (round_obj.ROUND_NAME or "").strip()
            meeting_link = None
            meeting_time = None

            # 🧩 1️⃣ For GD
            if "group discussion" in round_type or "gd" in round_name.lower():
                gd_record = TBL_GD_GROUP.objects.filter(JOB=job, COMPANY=company).first()
                if gd_record:
                    meeting_link = gd_record.MEETING_LINK
                    meeting_time = gd_record.SCHEDULE

            # 🧩 2️⃣ For Technical / HR Interviews
            elif "interview" in round_type:
                interview = TBL_INTERVIEW_SCHEDULE.objects.filter(
                    APPLICATION__STUDENT=student,
                    APPLICATION__JOB=job,
                    ROUND=round_obj,
                    COMPANY=company
                ).first()
                if interview:
                    meeting_link = interview.INTERVIEW_LINK
                    meeting_time = interview.INTERVIEW_DATE

            # ✅ Meeting Active Logic (fixed)
            is_meeting_active = False
            meeting_status = "Not Scheduled"

            if meeting_time:
                meeting_time = timezone.localtime(meeting_time)  # make timezone-aware
                # Allow meeting to be considered active from 15 mins before start till end of day
                start_window = meeting_time - timedelta(minutes=15)
                end_window = meeting_time + timedelta(hours=3)  # meeting window duration

                if start_window <= now <= end_window:
                    is_meeting_active = True
                    meeting_status = "Active"
                elif now < start_window:
                    meeting_status = "Upcoming"
                else:
                    meeting_status = "Expired"

            print(
                f"🔹 [DEBUG] Round {round_obj.ROUND_ID} ({round_name}) | "
                f"Type: {round_type} | Status: {meeting_status} | "
                f"Meeting Time: {meeting_time} | Now: {now}"
            )

            # ✅ Append final quiz data
            available_quizzes.append({
                "QUIZ_ID": round_obj.ROUND_ID,
                "TITLE": round_name,
                "DURATION": round_obj.ROUND_DURATION,
                "START_DATE": round_obj.ROUND_DATE,
                "ALREADY_ATTEMPTED": already_attempted,
                "ROUND_TYPE": round_obj.ROUND_TYPE or "Aptitude",
                "MEETING_LINK": meeting_link,
                "MEETING_ACTIVE": is_meeting_active,
                "MEETING_STATUS": meeting_status,
                "JOB": {
                    "TITLE": getattr(job, "JOB_TITLE", "N/A"),
                    "DESCRIPTION": getattr(job, "JOB_DESCRIPTION", "N/A"),
                },
                "COMPANY": {"NAME": company.COMPANY_NAME},
            })

        return render(request, "student-test.html", {
            "available_quizzes": available_quizzes
        })

    except Exception as e:
        print("❌ [ERROR in student_test]:", str(e))
        messages.error(request, f"Error fetching available tests: {e}")
        return redirect("studentDashboard")

# ✅ 2. Start Quiz (with debug)
@login_required_role(['student'])
def student_start_quiz(request, round_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired.")
            return redirect("login")

        student = TBL_STUDENT.objects.get(USER_id=user_id)
        round_obj = get_object_or_404(TBL_PLACEMENT_ROUND, ROUND_ID=round_id)

        applied = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=round_obj.JOB).exists()
        if not applied:
            messages.warning(request, "You are not authorized for this test.")
            return redirect("studentTest")

        quiz = TBL_QUIZ.objects.filter(JOB=round_obj.JOB).first()
        if not quiz:
            messages.error(request, "No quiz found for this job.")
            return redirect("studentTest")

        questions = TBL_QUIZ_QUESTION.objects.filter(QUIZ=quiz).order_by("QUESTION_ID")
        print(f"🟩 [DEBUG] Loaded {questions.count()} questions for Quiz {quiz.QUIZ_ID}")

        context = {
            "student": student,
            "round": round_obj,
            "job": round_obj.JOB,
            "company": round_obj.COMPANY,
            "quiz": quiz,
            "questions": questions,
            "duration": round_obj.ROUND_DURATION or 30,
        }
        return render(request, "student-quiz-screen.html", context)

    except Exception as e:
        print("❌ [ERROR in student_start_quiz]:", str(e))
        messages.error(request, f"Unable to load quiz: {e}")
        return redirect("studentTest")


# ✅ 3. Submit Quiz (debug + proper save)
@login_required_role(['student'])
@transaction.atomic
def submit_quiz(request, round_id):
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            messages.error(request, "Session expired.")
            return redirect("login")

        student = TBL_STUDENT.objects.get(USER_id=user_id)
        round_obj = get_object_or_404(TBL_PLACEMENT_ROUND, ROUND_ID=round_id)
        job = round_obj.JOB
        company = round_obj.COMPANY
        college = student.COLLEGE

        quiz = TBL_QUIZ.objects.filter(JOB=job).first()
        if not quiz:
            print("❌ [DEBUG] No quiz found for this job.")
            messages.error(request, "Quiz not found for this job.")
            return redirect("studentTest")

        questions = TBL_QUIZ_QUESTION.objects.filter(QUIZ=quiz)
        total_questions = questions.count()
        score = 0
        print(f"🟩 [DEBUG] Submitting {total_questions} questions for Student {student.STUDENT_NAME}")

        # Remove old answers
        deleted_count, _ = TBL_STUDENT_ANSWER.objects.filter(STUDENT=student, QUIZ_ID=quiz, JOB=job).delete()
        print(f"🟨 [DEBUG] Deleted old answers: {deleted_count}")

        for q in questions:
            selected = request.POST.get(f"question_{q.pk}")
            if not selected:
                print(f"⚠️ [DEBUG] Question {q.pk} skipped.")
                continue

            is_correct = (selected == q.CORRECT_OPTION)
            if is_correct:
                score += 1

            TBL_STUDENT_ANSWER.objects.create(
                STUDENT=student,
                QUESTION=q,
                QUIZ_ID=quiz,
                JOB=job,
                SELECTED_OPTION=selected,
                IS_CORRECT=is_correct
            )

        print(f"🟩 [DEBUG] Student Score: {score}")

        # Passing criteria
        passing_score = getattr(quiz, "QUIZ_PASS", 1)
        print(f"🟩 [DEBUG] Passing Score Requirement: {passing_score}")

        status = "Passed" if score >= passing_score else "Failed"

        # ✅ Remove any duplicate result entries first (safety check)
        duplicates = TBL_ROUND_RESULT.objects.filter(
            STUDENT=student, JOB=job, ROUND=round_obj
        )
        if duplicates.count() > 1:
            print(f"⚠️ [DEBUG] Found {duplicates.count()} duplicates for {student.STUDENT_NAME} — cleaning up.")
            duplicates.exclude(pk=duplicates.order_by('-UPDATED_AT').first().pk).delete()

        # ✅ Create or update final result
        result_obj, created = TBL_ROUND_RESULT.objects.update_or_create(
            STUDENT=student,
            JOB=job,
            COMPANY=company,
            COLLEGE=college,
            ROUND=round_obj,
            defaults={
                "ROUND_NUMBER": getattr(round_obj, "ROUND_NUMBER", 1),
                "RESULT_STATUS": status,
                "REMARKS": f"Scored {score}/{total_questions} (Pass Mark: {passing_score})",
                "UPDATED_AT": timezone.now(),
            }
        )

        count_check = TBL_ROUND_RESULT.objects.filter(
            STUDENT=student, JOB=job, ROUND=round_obj
        ).count()
        print(f"🟢 [DEBUG] Round result count after update: {count_check}")

        # ✅ Update Application Status when passed
        if status == "Passed":
            application = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).first()
            if application:
                current_status = application.APPLICATION_STATUS

                # Determine next stage
                next_status = None
                round_name = (round_obj.ROUND_NAME or "").lower()

                if "aptitude" in round_name:
                    next_status = "Technical/GD"
                elif "technical" in round_name and "interview" not in round_name:
                    next_status = "Technical Interview"
                elif "technical interview" in round_name:
                    next_status = "HR Interview"
                elif "hr" in round_name:
                    next_status = "Selected"  # ✅ Final stage

                if next_status:
                    print(f"🟩 [DEBUG] Updating {student.STUDENT_NAME}'s application from {current_status} → {next_status}")
                    application.APPLICATION_STATUS = next_status
                    application.save(update_fields=["APPLICATION_STATUS"])
        elif status == "Failed":
            application = TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).first()
            if application:
                print(f"❌ [DEBUG] {student.STUDENT_NAME} failed in {round_obj.ROUND_NAME}. Marking application as Rejected.")
                application.APPLICATION_STATUS = "Rejected"
                application.save(update_fields=["APPLICATION_STATUS"])


        messages.success(
            request,
            f"✅ Test submitted! You scored {score}/{total_questions}. Required: {passing_score} → {status}"
        )
        return redirect("studentTest")

    except Exception as e:
        print("❌ [ERROR in submit_quiz]:", str(e))
        messages.error(request, f"Error submitting quiz: {e}")
        return redirect("studentTest")

@login_required_role(['student'])
@never_cache
def student_profile(request):
    try:
        # --- Logged-in student ---
        user_id = request.session.get('user_id')
        if not user_id:
            messages.error(request, "Session expired. Please log in again.")
            return redirect('login')
        user = TBL_USER.objects.get(pk=user_id)

        # --- Get/Create Student Profile ---
        student, created = TBL_STUDENT.objects.get_or_create(
            USER=user,
            defaults={
                'STUDENT_NAME': user.USER_NAME,
                'STUDENT_EMAIL': user.EMAIL,
                'STUDENT_PHONE_NO': '',
                'STUDENT_PROFILE_PHOTO': None,
                'STUDENT_CURRENT_SEMSETER': '',
                'STUDENT_BRANCH': '',
                'STUDENT_COURSE': '',
                'STUDENT_PERMANENT_ADDRESS': '',
                'STUDENT_CURRENT_ADDRESS': '',
                'STUDENT_LINKEDIN_URL': '',
                'STUDENT_GITHUB_LINK': '',
                'STUDENT_PERSONAL_WEBSITE_PORTFOLIO': '',
                'STUDENT_RESUME': None,
            }
        )

    except TBL_USER.DoesNotExist:
        messages.error(request, "User not found! Please log in again.")
        return redirect('login')

    # ===============================
    # POST HANDLING
    # ===============================
    if request.method == "POST":
        print("POST data received:", request.POST)

        # ---------------------------------
        # 1️⃣ PERSONAL INFO UPDATE
        # ---------------------------------
        if 'STUDENT_ENROLLMENT_NUMBER' in request.POST:
            try:
                new_email = request.POST.get('STUDENT_EMAIL', '').strip()
                new_phone = request.POST.get('STUDENT_PHONE_NO', '').strip()
                new_enroll = request.POST.get('STUDENT_ENROLLMENT_NUMBER', '').strip()

                # --- Uniqueness Checks ---
                if TBL_STUDENT.objects.filter(~Q(pk=student.pk), STUDENT_EMAIL=new_email).exists():
                    messages.error(request, "This email is already in use.", extra_tags='personal')
                    return redirect('studentProfile')
                if new_phone and TBL_STUDENT.objects.filter(~Q(pk=student.pk), STUDENT_PHONE_NO=new_phone).exists():
                    messages.error(request, "This phone number is already in use.", extra_tags='personal')
                    return redirect('studentProfile')
                if new_enroll and TBL_STUDENT.objects.filter(~Q(pk=student.pk), STUDENT_ENROLLMENT_NUMBER=new_enroll).exists():
                    messages.error(request, "This enrollment number is already in use.", extra_tags='personal')
                    return redirect('studentProfile')

                # --- Update Fields ---
                student.STUDENT_NAME = request.POST.get('STUDENT_NAME', student.STUDENT_NAME).strip()
                student.STUDENT_EMAIL = new_email
                student.STUDENT_PHONE_NO = new_phone
                student.STUDENT_ROLL_NO = request.POST.get('STUDENT_ROLL_NO', student.STUDENT_ROLL_NO)
                student.STUDENT_ENROLLMENT_NUMBER = new_enroll
                student.STUDENT_DATE_OF_BIRTH = request.POST.get('STUDENT_DATE_OF_BIRTH', student.STUDENT_DATE_OF_BIRTH)
                student.STUDENT_GENDER = request.POST.get('STUDENT_GENDER', student.STUDENT_GENDER)
                student.STUDENT_PERMANENT_ADDRESS = request.POST.get('STUDENT_PERMANENT_ADDRESS', student.STUDENT_PERMANENT_ADDRESS)
                student.STUDENT_CURRENT_ADDRESS = request.POST.get('STUDENT_CURRENT_ADDRESS', student.STUDENT_CURRENT_ADDRESS)
                student.STUDENT_CURRENT_SEMSETER = request.POST.get('STUDENT_CURRENT_SEMSETER', student.STUDENT_CURRENT_SEMSETER)

                # --- Profile Photo ---
                profile_photo = request.FILES.get('STUDENT_PROFILE_PHOTO')
                if profile_photo:
                    fs = FileSystemStorage(location='media/profile_photos/student/')
                    filename = fs.save(profile_photo.name, profile_photo)
                    student.STUDENT_PROFILE_PHOTO = os.path.join('profile_photos/student', filename)

                # --- Update user info ---
                user.USER_NAME = student.STUDENT_NAME
                user.EMAIL = student.STUDENT_EMAIL
                user.save()
                student.save()

                messages.success(request, "Profile updated successfully!", extra_tags='personal')

            except Exception as e:
                messages.error(request, f"Error updating profile: {str(e)}", extra_tags='personal')
            return redirect('studentProfile')

        # ---------------------------------
        # 2️⃣ CONTACT / SOCIAL UPDATE
        # ---------------------------------
        elif 'STUDENT_LINKEDIN_URL' in request.POST:
            try:
                linkedin = request.POST.get('STUDENT_LINKEDIN_URL', '').strip()
                github = request.POST.get('STUDENT_GITHUB_LINK', '').strip()
                website = request.POST.get('STUDENT_PERSONAL_WEBSITE_PORTFOLIO', '').strip()

                # --- Unique checks ---
                if linkedin and TBL_STUDENT.objects.filter(~Q(pk=student.pk), STUDENT_LINKEDIN_URL=linkedin).exists():
                    messages.error(request, "This LinkedIn URL is already in use.", extra_tags='contact')
                    return redirect('studentProfile')
                if github and TBL_STUDENT.objects.filter(~Q(pk=student.pk), STUDENT_GITHUB_LINK=github).exists():
                    messages.error(request, "This GitHub URL is already in use.", extra_tags='contact')
                    return redirect('studentProfile')
                if website and TBL_STUDENT.objects.filter(~Q(pk=student.pk), STUDENT_PERSONAL_WEBSITE_PORTFOLIO=website).exists():
                    messages.error(request, "This website is already in use.", extra_tags='contact')
                    return redirect('studentProfile')

                student.STUDENT_LINKEDIN_URL = linkedin
                student.STUDENT_GITHUB_LINK = github
                student.STUDENT_PERSONAL_WEBSITE_PORTFOLIO = website

                resume = request.FILES.get('STUDENT_RESUME')
                if resume:
                    student.STUDENT_RESUME = resume

                student.save()
                messages.success(request, "Contact & social links updated successfully!", extra_tags='contact')

            except Exception as e:
                messages.error(request, f"Error updating contact info: {str(e)}", extra_tags='contact')
            return redirect('studentProfile')

        # ---------------------------------
        # 3️⃣ PASSWORD CHANGE
        # ---------------------------------
        elif 'old_password' in request.POST:
            old_password = request.POST.get('old_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if not check_password(old_password, user.PASSWORD):
                messages.error(request, "Old password is incorrect.", extra_tags='password')
            elif new_password != confirm_password:
                messages.error(request, "New password and confirm password do not match.", extra_tags='password')
            else:
                user.PASSWORD = make_password(new_password)
                user.save()
                messages.success(request, "Password changed successfully!", extra_tags='password')
            return redirect('studentProfile')

        # ---------------------------------
        # 4️⃣ EDUCATION / INTERNSHIP / PROJECT / CERTIFICATION
        # ---------------------------------
        elif 'form_type' in request.POST:
            form_type = request.POST.get('form_type')
            print("Form type received:", form_type)

            try:
                # --- Education ---
                if form_type == "education":
                    education_id = request.POST.get("EDUCATION_ID")
                    level = request.POST.get("EDUCATION_LEVEL")
                    institute = request.POST.get("INSTITUTE_NAME")
                    board = request.POST.get("BOARD_UNIVERSITY")
                    yop = int(request.POST.get("YEAR_OF_PASSING") or 0)
                    percentage = Decimal(request.POST.get("PERCENTAGE") or 0)

                    if education_id:
                        edu = get_object_or_404(TBL_EDUCATION, pk=education_id, STUDENT=student)
                        edu.EDUCATION_LEVEL = level
                        edu.INSTITUTE_NAME = institute
                        edu.BOARD_UNIVERSITY = board
                        edu.YEAR_OF_PASSING = yop
                        edu.PERCENTAGE = percentage
                        edu.save()
                        messages.success(request, "Education updated successfully!", extra_tags='education')
                    else:
                        TBL_EDUCATION.objects.create(
                            STUDENT=student,
                            EDUCATION_LEVEL=level,
                            INSTITUTE_NAME=institute,
                            BOARD_UNIVERSITY=board,
                            YEAR_OF_PASSING=yop,
                            PERCENTAGE=percentage,
                        )
                        messages.success(request, "Education added successfully!", extra_tags='education')

                # --- Internship ---
                elif form_type == "internship":
                    internship_id = request.POST.get("INTERNSHIP_ID")
                    company = request.POST.get("INTERNSHIP_COMPANY")
                    title = request.POST.get("INTERNSHIP_TITLE")
                    domain = request.POST.get("INTERNSHIP_DOMAIN")
                    desc = request.POST.get("INTERNSHIP_DESCRIPTION")
                    start = parse_date(request.POST.get("INTERNSHIP_START_DATE") or "")
                    end = parse_date(request.POST.get("INTERNSHIP_END_DATE") or "")
                    certificate = request.POST.get("INTERNSHIP_CERTIFICATE")

                    if internship_id:
                        internship = get_object_or_404(TBL_INTERNSHIP, pk=internship_id, STUDENT=student)
                        internship.COMPANY = company
                        internship.INTERNSHIP_TITLE = title
                        internship.INTERNSHIP_DOMAIN = domain
                        internship.INTERNSHIP_DESCRIPTION = desc
                        internship.INTERNSHIP_START_DATE = start
                        internship.INTERNSHIP_END_DATE = end
                        internship.INTERNSHIP_CERTIFICATE = certificate
                        internship.save()
                        messages.success(request, "Internship updated successfully!", extra_tags='internship')
                    else:
                        TBL_INTERNSHIP.objects.create(
                            STUDENT=student,
                            COMPANY=company,
                            INTERNSHIP_TITLE=title,
                            INTERNSHIP_DOMAIN=domain,
                            INTERNSHIP_DESCRIPTION=desc,
                            INTERNSHIP_START_DATE=start,
                            INTERNSHIP_END_DATE=end,
                            INTERNSHIP_CERTIFICATE=certificate,
                        )
                        messages.success(request, "Internship added successfully!", extra_tags='internship')

                # --- Project ---
                elif form_type == "project":
                    project_id = request.POST.get("PROJECT_ID")
                    title = request.POST.get("PROJECT_TITLE")
                    desc = request.POST.get("PROJECT_DESCRIPTION")
                    domain = request.POST.get("PROJECT_DOMAIN")
                    role = request.POST.get("PROJECT_ROLE")
                    start = parse_date(request.POST.get("PROJECT_START_DATE") or "")
                    end = parse_date(request.POST.get("PROJECT_END_DATE") or "")
                    status = request.POST.get("PROJECT_STATUS")

                    if project_id:
                        project = get_object_or_404(TBL_PROJECT, pk=project_id, STUDENT=student)
                        project.PROJECT_TITLE = title
                        project.PROJECT_DESCRIPTION = desc
                        project.PROJECT_DOMAIN = domain
                        project.PROJECT_ROLE = role
                        project.PROJECT_START_DATE = start
                        project.PROJECT_END_DATE = end
                        project.PROJECT_STATUS = status
                        project.save()
                        messages.success(request, "Project updated successfully!", extra_tags='project')
                    else:
                        TBL_PROJECT.objects.create(
                            STUDENT=student,
                            PROJECT_TITLE=title,
                            PROJECT_DESCRIPTION=desc,
                            PROJECT_DOMAIN=domain,
                            PROJECT_ROLE=role,
                            PROJECT_START_DATE=start,
                            PROJECT_END_DATE=end,
                            PROJECT_STATUS=status,
                        )
                        messages.success(request, "Project added successfully!", extra_tags='project')

                # --- Certification ---
                elif form_type == "certification":
                    cert_id = request.POST.get("CERTIFICATE_ID")
                    name = request.POST.get("CERTIFICATE_NAME")
                    domain = request.POST.get("CERTIFICATE_DOMAIN")
                    authority = request.POST.get("CERTIFICATE_AUTHORITY")
                    date = parse_date(request.POST.get("CERTIFICATE_DATE") or "")
                    url = request.POST.get("CERTIFICATE_URL")

                    if cert_id:
                        cert = get_object_or_404(TBL_CERTIFICATION, pk=cert_id, STUDENT=student)
                        cert.CERTIFICATE_NAME = name
                        cert.CERTIFICATE_DOMAIN = domain
                        cert.CERTIFICATE_AUTHORITY = authority
                        cert.CERTIFICATE_DATE = date
                        cert.CERTIFICATE_URL = url
                        cert.save()
                        messages.success(request, "Certificate updated successfully!", extra_tags='certificate')
                    else:
                        TBL_CERTIFICATION.objects.create(
                            STUDENT=student,
                            CERTIFICATE_NAME=name,
                            CERTIFICATE_DOMAIN=domain,
                            CERTIFICATE_AUTHORITY=authority,
                            CERTIFICATE_DATE=date,
                            CERTIFICATE_URL=url,
                        )
                        messages.success(request, "Certificate added successfully!", extra_tags='certificate')

            except Exception as e:
                messages.error(request, f"Error saving {form_type}: {str(e)}", extra_tags=form_type)
            return redirect('studentProfile')

    # ===============================
    # CONTEXT
    # ===============================
    context = {
        "student": student,
        # ✅ Sort by latest date/year
        "educations": TBL_EDUCATION.objects.filter(STUDENT=student).order_by("-YEAR_OF_PASSING"),
        "internships": TBL_INTERNSHIP.objects.filter(STUDENT=student).order_by("-INTERNSHIP_END_DATE", "-INTERNSHIP_START_DATE"),
        "projects": TBL_PROJECT.objects.filter(STUDENT=student).order_by("-PROJECT_END_DATE", "-PROJECT_START_DATE"),
        "certifications": TBL_CERTIFICATION.objects.filter(STUDENT=student).order_by("-CERTIFICATE_DATE"),
    }
    return render(request, "student-profile.html", context)



@login_required_role(['student'])
@never_cache
def student_companies(request):
    # Fetch all job posts with related company details
    jobs = TBL_JOB.objects.select_related('COMPANY').order_by('-JOB_POSTED_DATE')

    context = {
        'jobs': jobs,
    }
    return render(request, 'student-companies.html', context)


# --------------------------------------------
# Job Details (for modal via AJAX)
# --------------------------------------------
@login_required_role(['student'])
def student_job_details(request, job_id):
    
    user_id = request.session.get('user_id')
    student = None

    # Identify logged-in student
    if user_id:
        try:
            user = TBL_USER.objects.get(pk=user_id)
            student = TBL_STUDENT.objects.get(USER=user)
        except (TBL_USER.DoesNotExist, TBL_STUDENT.DoesNotExist):
            pass

    try:
        job = TBL_JOB.objects.select_related('COMPANY').get(JOB_ID=job_id)
        company = job.COMPANY

        # Check if already applied
        already_applied = (
            TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).exists()
            if student else False
        )

        data = {
            "success": True,
            "job": {
                "JOB_ID": job.JOB_ID,
                "JOB_TITLE": job.JOB_TITLE,
                "JOB_DESCRIPTION": job.JOB_DESCRIPTION,
                "JOB_LOCATION": job.JOB_LOCATION,
                "JOB_SALARY": str(job.JOB_SALARY),
                "JOB_TYPE": job.JOB_TYPE,
                "JOB_STATUS": job.JOB_STATUS,
                "JOB_POSTED_DATE": job.JOB_POSTED_DATE.strftime('%Y-%m-%d'),
                "JOB_VACANCY": job.JOB_VACANCY,
                "COMPANY_NAME": company.COMPANY_NAME,
                "COMPANY_EMAIL": getattr(company, 'COMPANY_EMAIL', 'N/A'),
                "COMPANY_LOCATION": getattr(company, 'COMPANY_LOCATION', 'N/A'),
                "COMPANY_DESCRIPTION": getattr(company, 'COMPANY_DESCRIPTION', ''),
            },
            "already_applied": already_applied
        }
    except TBL_JOB.DoesNotExist:
        data = {"success": False, "message": "Job not found."}

    return JsonResponse(data)

@login_required_role(['student'])
def apply_job(request, job_id):
    
    if request.method != 'POST':
        return JsonResponse({"success": False, "message": "Invalid request method."})

    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({"success": False, "message": "Session expired. Please log in again."})

    try:
        user = TBL_USER.objects.get(pk=user_id)
        student = TBL_STUDENT.objects.get(USER=user)
        job = TBL_JOB.objects.get(pk=job_id)
    except (TBL_USER.DoesNotExist, TBL_STUDENT.DoesNotExist, TBL_JOB.DoesNotExist):
        return JsonResponse({"success": False, "message": "Student or Job not found."})

    # Check if already applied
    if TBL_APPLICATION.objects.filter(STUDENT=student, JOB=job).exists():
        return JsonResponse({"success": False, "message": "You have already applied for this job."})

    # Create new application
    TBL_APPLICATION.objects.create(
        STUDENT=student,
        JOB=job,
        APPLICATION_DATE=timezone.now(),
        APPLICATION_STATUS='Pending',
        RESUME=getattr(student, 'STUDENT_RESUME', '')  # Optional field from student profile
    )

    return JsonResponse({"success": True, "message": "Application submitted successfully!"})

from django.db.models import Q

@login_required_role(['student'])
@never_cache
def student_reports(request):
    try:
        user_id = request.session.get("user_id")
        student = TBL_STUDENT.objects.select_related("USER", "COLLEGE").get(USER_id=user_id)

        applications = (
            TBL_APPLICATION.objects
            .filter(STUDENT=student)
            .select_related("JOB__COMPANY")
            .order_by("JOB__COMPANY__COMPANY_NAME", "JOB__JOB_TITLE")
        )

        report_data = []
        company_names = set()  # 👈 collect distinct company names

        for app in applications:
            job = app.JOB
            company = job.COMPANY
            company_names.add(company.COMPANY_NAME)  # 👈 add to distinct list

            round_sequence = ["Aptitude", "Group Discussion", "Technical Interview", "HR Interview"]
            rounds_info = []
            last_passed = True

            for round_name in round_sequence:
                round_result = TBL_ROUND_RESULT.objects.filter(
                    STUDENT=student,
                    JOB=job,
                    ROUND__ROUND_NAME__icontains=round_name
                ).select_related("ROUND").first()

                if not round_result:
                    status = "Pending" if last_passed else "Not Eligible"
                    remarks = "—"
                else:
                    status = round_result.RESULT_STATUS or "Pending"
                    remarks = round_result.REMARKS or "—"

                if status != "Passed":
                    last_passed = False

                rounds_info.append({
                    "round": round_name,
                    "status": status,
                    "remarks": remarks
                })

            report_data.append({
                "job_title": job.JOB_TITLE,
                "company_name": company.COMPANY_NAME,
                "status": app.APPLICATION_STATUS or "Pending",
                "rounds": rounds_info
            })

        context = {
            "student": student,
            "reports": report_data,
            "distinct_companies": sorted(company_names),  # 👈 distinct list added here
        }

        return render(request, "student-reports.html", context)

    except Exception as e:
        print("❌ [Student Reports Error]:", e)
        messages.error(request, "Error loading student reports.")
        return redirect("studentDashboard")