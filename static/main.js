// Placeholder for advanced JS logic
// Add AJAX calls, dashboard logic, notifications, etc. here

// On page load
document.addEventListener('DOMContentLoaded', function() {
  // Any initialization code can go here
});

// Responsive navbar toggle
const navbarToggler = document.querySelector('.navbar-toggler');
if (navbarToggler) {
  navbarToggler.addEventListener('click', function() {
    document.getElementById('navbarNav').classList.toggle('show');
  });
}

// Feature card click events
const featureCards = document.querySelectorAll('.feature-card');
featureCards.forEach(card => {
  card.addEventListener('click', function() {
    // Example: navigate to dashboard
    if (card.querySelector('.bi-person-badge')) {
      window.location.href = 'admin-dashboard.html';
    } else if (card.querySelector('.bi-people')) {
      window.location.href = 'tnp-dashboard.html';
    } else if (card.querySelector('.bi-building')) {
      window.location.href = 'company-dashboard.html';
    } else if (card.querySelector('.bi-person')) {
      window.location.href = 'student-dashboard.html';
    }
  });
});

// Contact form submit animation
const contactForm = document.getElementById('contactForm');
if (contactForm) {
  contactForm.addEventListener('submit', function(e) {
    e.preventDefault();
    const btn = this.querySelector('button[type="submit"]');
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Sending...';
    setTimeout(() => {
      btn.innerHTML = 'Send Message';
      alert('Message sent!');
      this.reset();
    }, 1200);
  });
}
