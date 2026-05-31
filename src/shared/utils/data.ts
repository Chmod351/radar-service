import { CDN_PROVIDERS } from "./const";

export const cloudNoise = ["cloudflare", "akamai", "vercel", "fastly", "google-cloud","amazon"];


export const signatures = [
  { key: "cloudflare", id: CDN_PROVIDERS.CLOUDFLARE },
  { key: "cloudfront", id: CDN_PROVIDERS.CLOUDFRONT },
  { key: "akamai", id: CDN_PROVIDERS.AKAMAI },
  { key: "fastly", id: CDN_PROVIDERS.FASTLY },
  { key: "gse", id: CDN_PROVIDERS.GOOGLE_CDN },
  { key:"google-front",id:CDN_PROVIDERS.GOOGLE_CDN },
  { key: "x-amz-cf", id: CDN_PROVIDERS.CLOUDFRONT },
  { key: "cf-ray", id: CDN_PROVIDERS.CLOUDFLARE },    
];

// bun ya maneja user agents, toca migrar esto al binario de bun
export const USER_AGENTS :string[]= [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
];

export const noise:string[]= ["UncommonHeaders", "Cookies", "HttpOnly", "Content-Language", 
  "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security", 
  "X-Content-Type-Options", "Access-Control-Allow-Methods", 
  "Meta-Refresh-Redirect", "RedirectLocation", "PasswordField",
  "X-Powered-By"];

