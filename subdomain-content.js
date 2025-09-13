// Subdomain content router
  document.addEventListener('DOMContentLoaded', function() {
      const hostname = window.location.hostname;
      const subdomain = hostname.split('.')[0];

      // Hide all content sections initially
      document.querySelectorAll('[data-subdomain]').forEach(section => {
          section.style.display = 'none';
      });

      // Show content based on subdomain
      let targetSubdomain;

      if (hostname === 'soltecsol.com' || hostname === 'www.soltecsol.com') {
          targetSubdomain = 'company';
      } else if (subdomain === 'app') {
          targetSubdomain = 'app';
      } else if (subdomain === 'genyx') {
          targetSubdomain = 'genyx';
      } else if (subdomain === 'tos') {
          targetSubdomain = 'tos';
      } else if (subdomain === 'dpa') {
          targetSubdomain = 'dpa';
      } else if (subdomain === 'gdpr') {
          targetSubdomain = 'gdpr';
      } else if (subdomain === 'pricing') {
          targetSubdomain = 'pricing';
      } else if (subdomain === 'subscriptions') {
          targetSubdomain = 'subscriptions';
      } else if (subdomain === 'signup') {
          targetSubdomain = 'signup';
      } else if (subdomain === 'login') {
          targetSubdomain = 'login';
      } else if (subdomain === 'helpdesk') {
          targetSubdomain = 'helpdesk';
      } else {
          targetSubdomain = 'app'; // Default to app
      }

      // Show the appropriate content
      const targetSection = document.querySelector(`[data-subdomain="${targetSubdomain}"]`);
      if (targetSection) {
          targetSection.style.display = 'block';
      }
  });
