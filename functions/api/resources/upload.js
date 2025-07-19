export async function onRequestPost({ request, env }) {
  try {
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('multipart/form-data')) {
      return new Response('Expected multipart/form-data', { status: 400 });
    }

    const formData = await request.formData();
    const file     = formData.get('file');
    const title    = formData.get('title');
    const urlInput = formData.get('url');
    const type     = formData.get('type');
    const pinned   = formData.get('pinned') === 'true';
    const uploadedThumbnail = formData.get('thumbnail');

    if (!title) {
      return new Response('Missing title', { status: 400 });
    }

    let url = '';
    let thumbnail = '';

    // === CASE 1: FILE upload ===
    if (file && file instanceof File) {
      const filename = `${Date.now()}-${file.name}`;
      const key = `uploads/${filename}`;
      url = `https://files.danieltesting.space/${key}`;

      await env.MY_BUCKET.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });

      thumbnail = uploadedThumbnail || url;

    // === CASE 2: URL input ===
    } else if (urlInput) {
      url = urlInput;

      // Hardcoded thumbnails based on type
      const typeThumbnails = {
        website: 'https://cesw.danieltesting.space/assets/website.png',
        video: 'https://cesw.danieltesting.space/assets/video.png'
      };

      thumbnail = typeThumbnails[type] || urlInput;

    } else {
      return new Response('Missing file or URL', { status: 400 });
    }

    // Insert into D1
    await env.POSTS_DB.prepare(`
      INSERT INTO resources (title, created_date, url, pinned, thumbnail)
      VALUES (?, datetime('now'), ?, ?, ?)
    `)
    .bind(title, url, pinned ? 1 : 0, thumbnail)
    .run();

    return new Response(JSON.stringify({ success: true, url }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (err) {
    console.error('Upload error:', err);
    return new Response(
      JSON.stringify({ error: 'Upload failed', details: err.message || String(err) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
