HireVerse – Intelligent University Placement Portal


🧭 Overview


HireVerse is a Django-based Placement Management System that bridges the gap between Students, Companies, TNP (Training & Placement) Cells, and University Admins.
It automates every stage of the campus recruitment lifecycle — from job posting, aptitude testing, and interview management to final placement tracking — all within a single platform.


🎯 Objectives


Centralize the placement process for colleges and universities.

Enable students to showcase their profiles, skills, and achievements.

Simplify company recruitment workflows (job posting, quizzes, interviews).

Empower TNP coordinators with dashboards and analytics.

Enhance transparency, automation, and traceability of placement data.


🧱 Key Highlights

Feature	Description
        🔐 Role-Based Access	Four distinct dashboards: Admin, TNP, Company, Student
        🧠 AI & Automation	Automated quiz evaluation, scoring, and analytics
        📊 Dashboard Analytics	Visual representation of placement metrics
        📑 Digital Portfolio	Student profiles with projects, internships, and certifications
        🧾 Job Lifecycle	Job creation → Application → Aptitude → GD → Interview → Offer
        💬 Real-time Communication	Built-in chat and notifications
        🗃️ Reports & Logs	Admin-level access to placement summaries and logs
        🧩 Custom Commands	Background reminders and automated scheduling
        💾 Secure File Storage	Managed uploads for resumes, certificates, and photos

        
🧰 Tech Stack
Layer	Technology Used
Frontend	HTML5, CSS3, JavaScript, Bootstrap 5.3
Backend	Django (Python 3.10+)
Database	SQLite (default) / PostgreSQL (production)
Authentication	Django Auth System (Role-based)
Automation	Custom AI utilities (ai_utils.py)
Task Scheduling	Django Management Commands + Cron
Version Control	Git & GitHub
Deployment	Gunicorn + Nginx (Linux Server)


🧩 System Architecture
        ┌─────────────────────────────────────┐
        │             Admin                   │
        │  ─ Manage Colleges & TNPs           │
        │  ─ Oversee Companies & Students     │
        │  ─ Access Reports & Analytics       │
        └─────────────────────────────────────┘
                          │
                          ▼
        ┌─────────────────────────────────────┐
        │           TNP Cell Members           │
        │  ─ Approve/Reject Company Jobs       │
        │  ─ Manage Student Applications       │
        │  ─ Schedule GD & Interview Rounds    │
        └─────────────────────────────────────┘
                          │
                          ▼
        ┌─────────────────────────────────────┐
        │              Companies               │
        │  ─ Create Job Posts & Quizzes        │
        │  ─ Evaluate Students in Rounds       │
        │  ─ Generate Placement Offers         │
        └─────────────────────────────────────┘
                          │
                          ▼
        ┌─────────────────────────────────────┐
        │              Students                │
        │  ─ Build Resume/Profile              │
        │  ─ Apply for Jobs                    │
        │  ─ Attend Quizzes & Interviews       │
        │  ─ Track Application Status          │
        └─────────────────────────────────────┘


📂 Project Directory Structure
HIREVERSE/
│
├── manage.py
├── requirements.txt
├── HIRE/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py               # Database Schema
│   ├── views.py                # Application Logic
│   ├── urls.py                 # URL Routing
│   ├── utils.py                # Helper Functions
│   ├── ai_utils.py             # AI / Automation Features
│   ├── decorators.py           # Role-based Access Control
│   ├── middleware.py           # Request/Response Middleware
│   ├── templates/              # HTML Templates
│   │   ├── admin/
│   │   ├── company/
│   │   ├── tnp/
│   │   └── student/
│   ├── static/                 # CSS, JS, Images
│   ├── management/
│   │   └── commands/
│   │       └── send_round_reminders.py
│   └── migrations/
└── README.md


⚙️ Installation Guide

1️⃣ Clone the Repository

git clone https://github.com/<your-username>/HireVerse.git

cd HireVerse/HIREVERSE


2️⃣ Set Up Virtual Environment

python -m venv venv

source venv/bin/activate     # macOS/Linux

venv\Scripts\activate        # Windows


3️⃣ Install Required Packages

pip install -r requirements.txt


4️⃣ Configure Environment Variables

Create a .env file in the project root:
        
        SECRET_KEY=your_django_secret_key
        DEBUG=True
        DATABASE_URL=sqlite:///db.sqlite3
        EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
        EMAIL_HOST=smtp.gmail.com
        EMAIL_PORT=587
        EMAIL_USE_TLS=True
        EMAIL_HOST_USER=your_email@gmail.com
        EMAIL_HOST_PASSWORD=your_password

5️⃣ Apply Database Migrations
        
        python manage.py makemigrations
        python manage.py migrate

6️⃣ Create Admin User

        python manage.py createsuperuser

7️⃣ Run the Development Server

        python manage.py runserver


Visit 👉 http://127.0.0.1:8000

🧩 Default User Roles

Role	Dashboard URL	Permissions
Admin	/admin_dashboard/	Manage all data & analytics
TNP Head	/tnp_dashboard/	Manage colleges, students, and job postings
Company	/company_dashboard/	Create jobs, quizzes, and conduct placement rounds
Student	/student_dashboard/	Apply for jobs, attend quizzes, and view placement results


🧱 Database Schema (Core Models)


Model	Description
TblUser	Base user model for authentication
TblAdmin, TblTnp, TblCompany, TblStudent	Role-specific user profiles
TblJob	Job postings created by companies
TblApplication	Applications submitted by students
TblQuiz, TblQuestion	Aptitude/coding test management
TblPlacementRound, TblRoundResult	Round progression tracking
TblInterviewSchedule	Interview details and modes
TblNotification, TblChatRoom	Communication modules
TblActivityLog, TblLoginHistory	System tracking and audit logs


📡 API Endpoints (Optional Extension)
Endpoint	Method	Description
/api/jobs/	GET	List all job postings
/api/apply/<job_id>/	POST	Apply for a specific job
/api/quiz/<job_id>/	GET/POST	Start or submit a quiz
/api/notifications/	GET	Retrieve user notifications

(These can be implemented using Django REST Framework if REST APIs are required.)


📈 Analytics & Reporting

Job-wise applicant statistics

Company placement ratio

Student performance tracking

Department-wise placement count

Round-wise progress visualization


🔔 Background Tasks

Custom Django commands automate repetitive tasks:

send_round_reminders.py: Sends email reminders for upcoming placement rounds.

Can be scheduled via cron jobs or Celery beat.


💬 Communication & Notifications

Chat module: Real-time chat between students, TNP, and companies.

Notification system: Alerts users for updates, new jobs, and results.

Activity logs: Track every user’s interactions.


🎨 Frontend Design

Built with Bootstrap 5.3 and custom CSS.

Features clean white cards, rounded corners, soft shadows, and a modern blue-accent theme.

Each dashboard (Admin, TNP, Company, Student) uses consistent responsive design.


🚀 Deployment Guide

Option 1: Local Deployment

        Run using Django’s development server (python manage.py runserver).

Option 2: Production Deployment

        Set DEBUG=False and configure ALLOWED_HOSTS.
        
        Use Gunicorn as WSGI server.
        
        Serve static files with Nginx.
        
        Configure PostgreSQL for production.
        
        Enable HTTPS with Certbot + Let’s Encrypt.


🧪 Testing

To run automated tests:

        python manage.py test


You can add test cases inside HIRE/tests.py.


🤝 Contribution Guide


Contributions are welcome!
To contribute:

        Fork the repository.
        
        Create a new feature branch:
        
        git checkout -b feature/<feature-name>


Commit your changes:

        git commit -m "Added new feature: <feature-name>"


Push the branch:

        git push origin feature/<feature-name>


Open a Pull Request on GitHub.


🧠 Future Enhancements

 AI-based candidate ranking system

 Resume parsing using NLP

 Real-time WebSocket chat (Django Channels)

 Email-based verification and OTP login

 Integration with LinkedIn/Indeed for job sync

 College-wide placement statistics dashboard


👨‍💻 Contributors

Name	Role	Contribution
Your Name	Project Lead	Backend, Architecture, Design
Team Member 1	Developer	Django Views & Models
Team Member 2	UI/UX	Frontend & Bootstrap Integration
Team Member 3	QA / Testing	Test cases, Validation


📜 License

This project is licensed under the MIT License.
You are free to use, modify, and distribute it under the same terms.


⭐ Acknowledgements

Django Documentation

Bootstrap Framework

Chart.js for analytics

OpenAI for AI utility inspiration

Stack Overflow and GitHub Community
