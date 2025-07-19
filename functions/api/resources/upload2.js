const file = formData.get('file');
const urlInput = formData.get('url');
const type = formData.get('type');
let url = '';
let thumbnail = '';

// Determine if using uploaded file or external URL
if (file && file instanceof File) {
  const filename = `${Date.now()}-${file.name}`;
  const key = `uploads/${filename}`;
  url = `https://files.danieltesting.space/${key}`;

  await env.MY_BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type }
  });

  // Check for uploaded thumbnail (from PDF processing or image preview)
  thumbnail = formData.get('thumbnail');
} else if (urlInput && typeof urlInput === 'string') {
  url = urlInput;

  // Set generic thumbnail based on type
  const typeThumbMap = {
    website: 'https://example.com/thumbs/website.png',
    video: 'https://example.com/thumbs/video.png'
  };
  thumbnail = typeThumbMap[type] || 'https://example.com/thumbs/default.png';
}

// Fallback to URL if no image thumbnail
if (!thumbnail) thumbnail = url;

// Save to D1
await env.POSTS_DB.prepare(`
  INSERT INTO resources (title, created_date, url, pinned, thumbnail)
  VALUES (?, datetime('now'), ?, ?, ?)
`)
.bind(title, url, pinned ? 1 : 0, thumbnail)
.run();
