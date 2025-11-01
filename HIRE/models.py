from django.db import models
from django.contrib.auth.hashers import make_password

# -------------------------------
# ROLE TABLE
# -------------------------------
class TBL_ROLE(models.Model):
    ROLE_ID = models.AutoField(primary_key=True)
    ROLE_TYPE = models.CharField(max_length=25, unique=True)

    def __str__(self):
        return self.ROLE_TYPE


# -------------------------------
# USER TABLE
# -------------------------------
class TBL_USER(models.Model):
    USER_ID = models.AutoField(primary_key=True)
    USER_NAME = models.CharField(max_length=50)
    EMAIL = models.CharField(max_length=50, unique=True)
    PASSWORD = models.CharField(max_length=100)
    ROLE = models.ForeignKey(TBL_ROLE, on_delete=models.CASCADE)
    STATUS = models.CharField(max_length=20)
    CREATED_AT = models.DateTimeField(auto_now_add=True)

    @classmethod
    def reset_password(cls, email, new_password):
        try:
            user = cls.objects.get(EMAIL=email)
            user.PASSWORD = make_password(new_password)
            user.save()
            return True
        except cls.DoesNotExist:
            return False
        
    def __str__(self):
        return f"{self.USER_NAME} ({self.EMAIL})"


# -------------------------------
# EMAIL VERIFICATION
# -------------------------------
from django.utils import timezone
from datetime import timedelta
class TBL_EMAIL_VERIFICATION(models.Model):
    PURPOSE_CHOICES = (
        ('verify', 'Email Verification'),
        ('reset', 'Password Reset'),
    )
    user = models.ForeignKey('TBL_USER', on_delete=models.CASCADE)
    otp = models.CharField(max_length=6,default="")
    purpose = models.CharField(max_length=10, choices=PURPOSE_CHOICES,default="")
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at


# -------------------------------
# COLLEGE
# -------------------------------
class TBL_COLLEGE(models.Model):
    COLLEGE_ID = models.AutoField(primary_key=True)
    COLLEGE_NAME = models.CharField(max_length=100)
    COLLEGE_CODE = models.CharField(max_length=6, unique=True)
    COLLEGE_UNIVERSITY = models.CharField(max_length=100)
    COLLEGE_EMAIL = models.CharField(max_length=50, unique=True)
    COLLEGE_ADDRESS = models.CharField(max_length=50)
    COLLEGE_PHONE_NO = models.BigIntegerField(unique=True)
    COLLEGE_WEBSITE_URL = models.CharField(max_length=100, unique=True)
    COLLEGE_ESTABLISHED_YEAR = models.IntegerField()
    COLLEGE_CAMPUS_TYPE = models.CharField(max_length=10)
    COLLEGE_STATUS = models.CharField(max_length=10)
    COLLEGE_LOGO = models.ImageField(upload_to='college_logos/', null=True, blank=True)
    COLLEGE_CAMPUS_SIZE = models.IntegerField()
    COLLEGE_COURSE_OFFERED = models.CharField(max_length=100)
    COLLEGE_ACEDEMIC_STRUCTURE = models.CharField(max_length=100)
    COLLEGE_NOTES = models.CharField(max_length=500)
    USER = models.ForeignKey(TBL_USER, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.COLLEGE_NAME} ({self.COLLEGE_CODE})"


# -------------------------------
# TNP TABLE
# -------------------------------
class TBL_TNP(models.Model):
    TNP_ID = models.AutoField(primary_key=True)
    TNP_NAME = models.CharField(max_length=25)
    ROLE_TYPE = models.CharField(max_length=50, default='TNP MEMBER')
    COLLEGE = models.ForeignKey(TBL_COLLEGE, on_delete=models.CASCADE, null=True, blank=True)
    USER = models.ForeignKey(TBL_USER, on_delete=models.CASCADE)
    TNP_EMAIL = models.CharField(max_length=50, unique=True)
    TNP_PHONE_NO = models.BigIntegerField(unique=True,null=True, blank=True)
    TNP_PROFILE_PHOTO = models.ImageField(upload_to='profile_photos/tnp/', null=True, blank=True)
    TNP_DATE_OF_BIRTH = models.DateField(null=True, blank=True)
    TNP_PERMANENT_ADDRESS = models.CharField(max_length=255, null=True, blank=True)
    TNP_CURRENT_ADDRESS = models.CharField(max_length=255, null=True, blank=True)
    TNP_LINKEDIN_URL = models.URLField(max_length=250, unique=True, null=True, blank=True)
    TNP_GITHUB_LINK = models.URLField(max_length=250, null=True, blank=True)
    TNP_PERSONAL_WEBSITE_PORTFOLIO = models.URLField(max_length=250, null=True, blank=True)

    def __str__(self):
        return f"{self.TNP_NAME} ({self.COLLEGE.COLLEGE_NAME})"


# -------------------------------
# ADMIN TABLE
# -------------------------------
class TBL_ADMIN(models.Model):
    ADMIN_ID = models.AutoField(primary_key=True)
    ADMIN_NAME = models.CharField(max_length=25)
    ROLE_TYPE = models.CharField(max_length=50, default='ADMIN')
    USER = models.ForeignKey(TBL_USER, on_delete=models.CASCADE)
    ADMIN_EMAIL = models.CharField(max_length=50, unique=True)
    ADMIN_PHONE_NO = models.BigIntegerField(unique=True)
    ADMIN_PROFILE_PHOTO = models.ImageField(upload_to='profile_photos/admin/', null=True, blank=True)
    ADMIN_PERMANENT_ADDRESS = models.CharField(max_length=255)
    ADMIN_CURRENT_ADDRESS = models.CharField(max_length=255)

    def __str__(self):
        return self.ADMIN_NAME


# -------------------------------
# COMPANY TABLE
# -------------------------------
class TBL_COMPANY(models.Model):
    COMPANY_ID = models.AutoField(primary_key=True)
    COMPANY_NAME = models.CharField(max_length=100)
    ROLE_TYPE = models.CharField(max_length=50, default='COMPANY')
    USER = models.ForeignKey(TBL_USER, on_delete=models.CASCADE)
    COLLEGE = models.ForeignKey(TBL_COLLEGE, on_delete=models.CASCADE)
    COMPANY_EMAIL = models.CharField(max_length=50, unique=True)
    COMPANY_PHONE_NO = models.BigIntegerField(unique=True)
    COMPANY_PROFILE_PHOTO = models.ImageField(upload_to='profile_photos/company/', null=True, blank=True)
    COMPANY_DATE_OF_ESTABLISHMENT = models.DateField(blank=True, null=True)
    COMPANY_PERMANENT_ADDRESS = models.CharField(max_length=255, blank=True, null=True)
    COMPANY_SECONDARY_ADDRESS = models.CharField(max_length=255, blank=True, null=True)
    COMPANY_LINKEDIN_URL = models.CharField(max_length=250, unique=True, blank=True, null=True)
    COMPANY_WEBSITE = models.CharField(max_length=250, unique=True)
    COMPANY_INDUSTRY = models.CharField(max_length=150)

    def __str__(self):
        return self.COMPANY_NAME


# -------------------------------
# STUDENT TABLE
# -------------------------------
class TBL_STUDENT(models.Model):
    STUDENT_ID = models.AutoField(primary_key=True)
    STUDENT_NAME = models.CharField(max_length=50)
    STUDENT_ROLL_NO = models.CharField(max_length=25,unique=True, null=True, blank=True)
    ROLE_TYPE = models.CharField(max_length=50, default='STUDENT')
    COLLEGE = models.ForeignKey(TBL_COLLEGE, on_delete=models.CASCADE)
    USER = models.ForeignKey(TBL_USER, on_delete=models.CASCADE)
    STUDENT_EMAIL = models.CharField(max_length=50, unique=True)
    STUDENT_PHONE_NO = models.BigIntegerField(unique=True)
    STUDENT_PROFILE_PHOTO = models.ImageField(upload_to='profile_photos/tnp/', null=True, blank=True)
    STUDENT_DATE_OF_BIRTH = models.DateField(blank=True, null=True)
    STUDENT_PERMANENT_ADDRESS = models.CharField(max_length=255, blank=True, null=True)
    STUDENT_CURRENT_ADDRESS = models.CharField(max_length=255, blank=True, null=True)
    STUDENT_LINKEDIN_URL = models.CharField(max_length=255, unique=True, blank=True, null=True)
    STUDENT_GITHUB_LINK = models.CharField(max_length=255,unique=True, blank=True, null=True)
    STUDENT_PERSONAL_WEBSITE_PORTFOLIO = models.CharField(max_length=255, blank=True, null=True)
    STUDENT_GENDER = models.CharField(max_length=10, blank=True, null=True)
    STUDENT_ENROLLMENT_NUMBER = models.CharField(max_length=10, unique=True, blank=True, null=True)
    STUDENT_COURSE = models.CharField(max_length=25, blank=True, null=True)
    STUDENT_BRANCH = models.CharField(max_length=50, blank=True, null=True)
    STUDENT_CURRENT_SEMSETER = models.IntegerField( blank=True, null=True)
    STUDENT_CGPA = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    STUDENT_PERCENTAGE = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    STUDENT_BACKLOG = models.IntegerField(blank=True, null=True)
    STUDENT_YEAR_OF_PASSING = models.DateField(blank=True, null=True)
    STUDENT_TECHNICAL_SKILLS = models.CharField(max_length=255, blank=True, null=True)
    STUDENT_SOFT_SKILLS = models.CharField(max_length=255, blank=True, null=True)
    STUDENT_AREA_OF_INTEREST = models.CharField(max_length=255, blank=True, null=True)
    STUDENT_RESUME = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.STUDENT_NAME} ({self.COLLEGE.COLLEGE_NAME})"

# -------------------------------
# INTERNSHIP TABLE
# -------------------------------
class TBL_INTERNSHIP(models.Model):
    INTERNSHIP_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    COMPANY = models.CharField(max_length=255)
    INTERNSHIP_TITLE = models.CharField(max_length=100)
    INTERNSHIP_DOMAIN = models.CharField(max_length=100)
    INTERNSHIP_DESCRIPTION = models.TextField()
    INTERNSHIP_START_DATE = models.DateField()
    INTERNSHIP_END_DATE = models.DateField()
    INTERNSHIP_CERTIFICATE = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.INTERNSHIP_TITLE} - {self.STUDENT.STUDENT_NAME}"


# -------------------------------
# PROJECT TABLE
# -------------------------------
class TBL_PROJECT(models.Model):
    PROJECT_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    PROJECT_TITLE = models.CharField(max_length=100)
    PROJECT_DESCRIPTION = models.TextField()
    PROJECT_DOMAIN = models.CharField(max_length=100)
    PROJECT_ROLE = models.CharField(max_length=50)
    PROJECT_START_DATE = models.DateField()
    PROJECT_END_DATE = models.DateField()
    PROJECT_STATUS = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.PROJECT_TITLE} ({self.STUDENT.STUDENT_NAME})"


# -------------------------------
# CERTIFICATION TABLE
# -------------------------------
class TBL_CERTIFICATION(models.Model):
    CERTIFICATE_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    CERTIFICATE_NAME = models.CharField(max_length=100)
    CERTIFICATE_DOMAIN = models.CharField(max_length=100)
    CERTIFICATE_AUTHORITY = models.CharField(max_length=100)
    CERTIFICATE_DATE = models.DateField()
    CERTIFICATE_URL = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.CERTIFICATE_NAME} ({self.STUDENT.STUDENT_NAME})"


# -------------------------------
# EDUCATION TABLE
# -------------------------------
class TBL_EDUCATION(models.Model):
    EDUCATION_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    EDUCATION_LEVEL = models.CharField(max_length=50)
    INSTITUTE_NAME = models.CharField(max_length=100)
    BOARD_UNIVERSITY = models.CharField(max_length=100)
    YEAR_OF_PASSING = models.IntegerField()
    PERCENTAGE = models.DecimalField(max_digits=5, decimal_places=2)
    CGPA = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return f"{self.EDUCATION_LEVEL} - {self.STUDENT.STUDENT_NAME}"


# -------------------------------
# JOB TABLE
# -------------------------------
class TBL_JOB(models.Model):
    JOB_ID = models.AutoField(primary_key=True)
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE)
    JOB_TITLE = models.CharField(max_length=100)
    JOB_DESCRIPTION = models.TextField()
    JOB_VACANCY = models.IntegerField(default=0)
    JOB_LOCATION = models.CharField(max_length=100)
    JOB_SALARY = models.DecimalField(max_digits=10, decimal_places=2)
    JOB_TYPE = models.CharField(max_length=50)
    JOB_POSTED_DATE = models.DateField(auto_now_add=True)
    JOB_STATUS = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.JOB_TITLE} ({self.COMPANY.COMPANY_NAME})"


# -------------------------------
# APPLICATION TABLE
# -------------------------------
class TBL_APPLICATION(models.Model):
    APPLICATION_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE)
    APPLICATION_DATE = models.DateTimeField(auto_now_add=True)

    APPLICATION_STATUS_CHOICES = [
        ('Applied', 'Applied'),
        ('Aptitude', 'Aptitude Round'),
        ('Technical/GD', 'Technical / Group Discussion'),
        ('Technical Interview', 'Technical Interview'),
        ('HR Interview', 'HR Interview'),
        ('Selected', 'Selected'),
        ('Rejected', 'Rejected'),
        ('Completed', 'Process Completed'),
    ]
    APPLICATION_STATUS = models.CharField(
        max_length=50,
        choices=APPLICATION_STATUS_CHOICES,
        default='Applied'
    )

    RESUME = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.STUDENT.STUDENT_NAME} → {self.JOB.JOB_TITLE} ({self.APPLICATION_STATUS})"



# -------------------------------
# PLACEMENT ROUND
# -------------------------------
class TBL_PLACEMENT_ROUND(models.Model):
    ROUND_ID = models.AutoField(primary_key=True)
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE, default="")
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE, default="")
    COLLEGE = models.ForeignKey('TBL_COLLEGE', on_delete=models.CASCADE, default="")
    ROUND_NAME = models.CharField(max_length=50)
    ROUND_DATE = models.DateField()
    ROUND_DURATION = models.IntegerField(default=0)
    ROUND_TYPE = models.CharField(max_length=50)
    ROUND_DESCRIPTION = models.TextField()

    def __str__(self):
        return f"{self.ROUND_NAME} ({self.JOB.JOB_TITLE})"


# -------------------------------
# INTERVIEW SCHEDULE
# -------------------------------
class TBL_INTERVIEW_SCHEDULE(models.Model):
    INTERVIEW_ID = models.AutoField(primary_key=True)
    APPLICATION = models.ForeignKey('TBL_APPLICATION', on_delete=models.CASCADE, default="")
    ROUND = models.ForeignKey('TBL_PLACEMENT_ROUND', on_delete=models.CASCADE, default="")
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE, default="")
    COLLEGE = models.ForeignKey('TBL_COLLEGE', on_delete=models.CASCADE, default="")
    INTERVIEW_DATE = models.DateTimeField()
    INTERVIEW_MODE = models.CharField(max_length=50)
    INTERVIEW_MODE = models.CharField(max_length=50, default="Online")
    INTERVIEW_LINK = models.CharField(max_length=255, blank=True, null=True)
    INTERVIEW_STATUS = models.CharField(max_length=20, default="Scheduled")

    def __str__(self):
        return f"{self.APPLICATION.STUDENT.STUDENT_NAME} - {self.ROUND.ROUND_NAME}"


# -------------------------------
# ROUND RESULT
# -------------------------------
class TBL_ROUND_RESULT(models.Model):
    RESULT_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE)
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE)
    COLLEGE = models.ForeignKey('TBL_COLLEGE', on_delete=models.CASCADE)
    ROUND = models.ForeignKey('TBL_PLACEMENT_ROUND', on_delete=models.CASCADE, null=True, blank=True)

    ROUND_NUMBER = models.IntegerField(default=1)
    RESULT_STATUS = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Passed', 'Passed'), ('Failed', 'Failed')],
        default='Pending'
    )
    REMARKS = models.TextField(blank=True, null=True)
    UPDATED_AT = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["STUDENT", "JOB", "ROUND"],
                name="unique_student_job_round"
            )
        ]

    def __str__(self):
        return f"{self.STUDENT.STUDENT_NAME} - {self.JOB.JOB_TITLE} - Round {self.ROUND.ROUND_NAME}"

# -------------------------------
# QUIZ TABLE
# -------------------------------
class TBL_QUIZ(models.Model):
    QUIZ_ID = models.AutoField(primary_key=True)
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE, default="")
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE, default="")
    COLLEGE = models.ForeignKey('TBL_COLLEGE', on_delete=models.CASCADE, default="")
    QUIZ_TITLE = models.CharField(max_length=100)
    TOTAL_QUESTIONS = models.IntegerField()
    QUIZ_PASS = models.IntegerField(default=1)
    QUIZ_START_DATE = models.DateField(null=True, blank=True, default=None)
    QUIZ_END_DATE = models.DateField(null=True, blank=True, default=None)
    QUIZ_DURATION = models.IntegerField(help_text="Duration in minutes")
    QUIZ_DATE = models.DateField()
    def __str__(self):
        return f"{self.QUIZ_TITLE} ({self.JOB.JOB_TITLE})"


# -------------------------------
# QUIZ QUESTION TABLE
# -------------------------------
class TBL_QUIZ_QUESTION(models.Model):
    QUESTION_ID = models.AutoField(primary_key=True)
    QUIZ = models.ForeignKey('TBL_QUIZ', on_delete=models.CASCADE)
    QUESTION_TEXT = models.TextField()
    OPTION_A = models.CharField(max_length=255)
    OPTION_B = models.CharField(max_length=255)
    OPTION_C = models.CharField(max_length=255)
    OPTION_D = models.CharField(max_length=255)
    CORRECT_OPTION = models.CharField(max_length=1)

    def __str__(self):
        return f"Q{self.QUESTION_ID}: {self.QUESTION_TEXT[:50]}..."


# -------------------------------
# STUDENT ANSWER TABLE
# -------------------------------
class TBL_STUDENT_ANSWER(models.Model):
    ANSWER_ID = models.AutoField(primary_key=True)
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    QUESTION = models.ForeignKey('TBL_QUIZ_QUESTION', on_delete=models.CASCADE)
    QUIZ_ID = models.ForeignKey('TBL_QUIZ', on_delete=models.CASCADE, default="")
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE, default="")
    SELECTED_OPTION = models.CharField(max_length=1)
    IS_CORRECT = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.STUDENT.STUDENT_NAME} → Q{self.QUESTION.QUESTION_ID}"

class TBL_CODING_QUESTION(models.Model):
    QUESTION_ID = models.AutoField(primary_key=True)
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE, default="")
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE, default="")
    COLLEGE = models.ForeignKey('TBL_COLLEGE', on_delete=models.CASCADE, default="")
    QUESTION_TITLE = models.CharField(max_length=100)
    QUESTION_DESCRIPTION = models.TextField()
    DIFFICULTY = models.CharField(max_length=50)
    DURATION_MINUTES = models.IntegerField()

# ---------------------------
# 📘 models.py (fixed)
# ---------------------------

from django.utils import timezone

class TBL_GD_GROUP(models.Model):
    GROUP_ID = models.AutoField(primary_key=True)
    JOB = models.ForeignKey('TBL_JOB', on_delete=models.CASCADE)
    COMPANY = models.ForeignKey('TBL_COMPANY', on_delete=models.CASCADE)
    COLLEGE = models.ForeignKey('TBL_COLLEGE', on_delete=models.CASCADE)
    ROUND = models.ForeignKey('TBL_PLACEMENT_ROUND', on_delete=models.CASCADE, null=True, blank=True)

    GROUP_NUMBER = models.IntegerField(help_text="Group number for this GD session (e.g., 1, 2, 3...)")
    SCHEDULE = models.DateTimeField(help_text="Date & time of the GD session")
    MEETING_LINK = models.CharField(max_length=255, null=True, blank=True)
    STATUS = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Scheduled', 'Scheduled'), ('Link Sent', 'Link Sent')],
        default='Pending'
    )
    CREATED_AT = models.DateTimeField(default=timezone.now)  # ✅ only auto_now_add

    class Meta:
        unique_together = ('JOB', 'GROUP_NUMBER')
        ordering = ['GROUP_NUMBER']

    def __str__(self):
        return f"{self.JOB.JOB_TITLE} | Group {self.GROUP_NUMBER} ({self.COMPANY.COMPANY_NAME})"



class TBL_GD_GROUP_MEMBER(models.Model):
    GROUP_MEMBER_ID = models.AutoField(primary_key=True)
    GROUP = models.ForeignKey('TBL_GD_GROUP', on_delete=models.CASCADE, related_name="members")
    STUDENT = models.ForeignKey('TBL_STUDENT', on_delete=models.CASCADE)
    JOINED_AT = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('GROUP', 'STUDENT')

    def __str__(self):
        return f"{self.STUDENT.STUDENT_NAME} → Group {self.GROUP.GROUP_NUMBER}"



# -------------------------------
# NOTIFICATION TABLE
# -------------------------------
class TBL_NOTIFICATION(models.Model):
    NOTIFICATION_ID = models.AutoField(primary_key=True)
    USER = models.ForeignKey('TBL_USER', on_delete=models.CASCADE)
    TITLE = models.CharField(max_length=100)
    MESSAGE = models.TextField()
    CREATED_AT = models.DateTimeField(auto_now_add=True)
    IS_READ = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.TITLE} ({'Read' if self.IS_READ else 'Unread'})"


# -------------------------------
# LOGIN HISTORY
# -------------------------------
class TBL_LOGIN_HISTORY(models.Model):
    LOGIN_ID = models.AutoField(primary_key=True)
    USER = models.ForeignKey('TBL_USER', on_delete=models.CASCADE)
    LOGIN_TIME = models.DateTimeField(auto_now_add=True)
    LOGOUT_TIME = models.DateTimeField(blank=True, null=True)
    IP_ADDRESS = models.GenericIPAddressField()
    DEVICE_INFO = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.USER.USER_NAME} ({self.LOGIN_TIME})"