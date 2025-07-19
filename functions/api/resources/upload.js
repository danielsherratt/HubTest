export async function onRequestPost({ request, env }) {
  try {
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('multipart/form-data')) {
      return new Response('Expected multipart/form-data', { status: 400 });
    }

    const formData = await request.formData();
    const file = formData.get('file');
    const title = formData.get('title');
    const pinned = formData.get('pinned') === 'true';
    const thumbnail = formData.get('thumbnail') || url;

    if (!file || !(file instanceof File) || !title) {
      return new Response('Missing file or title', { status: 400 });
    }

    const filename = `${Date.now()}-${file.name}`;
    const key = `uploads/${filename}`;
    const url = `https://files.danieltesting.space/${key}`;

    // Upload to R2
    await env.MY_BUCKET.put(key, file.stream(), {
      httpMetadata: { contentType: file.type }
    });

    // Insert into D1
    await env.POSTS_DB.prepare(`
      INSERT INTO resources (title, created_date, url, pinned, thumbnail)
      VALUES (?, datetime('now'), ?, ?, ?)
    `)
    .bind(title, url, pinned ? 1 : 0, thumbnail || null)
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
