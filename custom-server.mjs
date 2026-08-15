import { createServer } from 'http';
import { parse } from 'url';
import next from 'next';

const port = parseInt(process.env.PORT || '3000', 10);
const dev = process.env.NODE_ENV !== 'production';

const app = next({ dev, port });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const server = createServer((req, res) => {
    const parsedUrl = parse(req.url, true);
    handle(req, res, parsedUrl);
  });

  // Keep-alive with short timeout
  server.keepAliveTimeout = 1000;
  server.headersTimeout = 1500;
  
  server.listen(port, () => {
    console.log(`> Ready on http://localhost:${port}`);
  });
});
