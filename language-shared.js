// Function to initialize language from URL parameter
function initializeLanguageFromURL() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('lang');
}

// Function to update links with language parameter
function updateNavigationLinks(lang) {
  const links = document.querySelectorAll('a');
  links.forEach(link => {
    // Only update internal links or links to your domains
    if (link.href.includes('soltecsol.com')) {
      const url = new URL(link.href);
      url.searchParams.set('lang', lang);
      link.href = url.toString();
    }
  });
}