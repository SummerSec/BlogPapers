const SitemapGenerator = require('sitemap-generator');


// create generator
const generator = SitemapGenerator('http://sumsec.me', {
    stripQuerystring: false,
    filepath: '/home/runner/work/BlogPapers/BlogPapers/resources/sitemap.xml'
});


// register event listeners
generator.on('done', () => {
  // sitemaps created
});

// start the crawler
generator.start();

