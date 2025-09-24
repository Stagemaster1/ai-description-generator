// Function to initialize language from URL parameter
function initializeLanguageFromURL() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('lang');
}

// Function to update links with language parameter
function updateNavigationLinks(lang) {
  const links = document.querySelectorAll('a');
  links.forEach(link => {
    console.log('Selected Link:', link.href);
    // Only update internal links or links to your domains
    if (link.href.includes('soltecsol.com')) {
      try {
        const url = new URL(link.href);
        console.log('Original URL:', url.toString());
        url.searchParams.set('lang', lang);
        console.log('Modified URL:', url.toString());
        link.href = url.toString();
      } catch (error) {
        console.error('Error updating link:', link.href, error);
      }
    }
  });
}