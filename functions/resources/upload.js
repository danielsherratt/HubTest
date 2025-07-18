export async function onRequestPost({ request, env }) {
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return new Response('Expected multipart/form-data', { status: 400 });
  }

  const formData = await request.formData();
  const file = formData.get('file');
  const title = formData.get('title');
  const pinned = formData.get('pinned') === 'true';

  if (!file || !(file instanceof File) || !title) {
    return new Response('Missing file or title', { status: 400 });
  }

  // Generate unique filename
  const filename = `${Date.now()}-${file.name}`;
  const key = `uploads/${filename}`;
  const bucketUrl = `https://files.danieltesting.space/${key}`;

  try {
    // Upload file to R2 bucket
    await env.MY_BUCKET.put(key, file.stream(), {
      httpMetadata: {
        contentType: file.type
      }
    });

    // Insert metadata into D1 table `resources`
    await env.DB.prepare(`
      INSERT INTO resources (title, created_date, url, pinned)
      VALUES (?, datetime('now'), ?, ?)
    `)
    .bind(title, bucketUrl, pinned ? 1 : 0)
    .run();

    return new Response(JSON.stringify({ success: true, url: bucketUrl }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (err) {
    console.error('Upload failed:', err);
    return new Response('Upload failed', { status: 500 });
  }
}
