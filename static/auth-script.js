// Test credentials for each role
const testUsers = [
  { role: 'admin', email: 'admin123@gmail.com', password: 'admin123', dashboard: 'admin-dashboard.html' },
  { role: 'tnp', email: 'tnp123@gmail.com', password: 'tnp123', dashboard: 'tnp-dashboard.html' },
  { role: 'company', email: 'company123@gmail.com', password: 'company123', dashboard: 'company-dashboard.html' },
  { role: 'student', email: 'student123@gmail.com', password: 'student123', dashboard: 'student-dashboard.html' }
];

// Login form handler
window.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.querySelector('#login form');
  if (loginForm) {
    loginForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value.trim();
      const role = document.getElementById('loginRole').value;
      const user = testUsers.find(u => u.role === role && u.email === email && u.password === password);
      if (user) {
        window.location.href = user.dashboard;
      } else {
        alert('Invalid credentials! Please use the test credentials for each role.');
      }
    });
  }
});
