export async function onRequestDelete({ env, params }) {
  const id = params.id;
  if (!id) return new Response('Missing ID', { status: 400 });

  try {
    // Look up the resource
    const { results } = await env.DB.prepare(`
      SELECT url FROM resources WHERE id = ?
    `).bind(id).all();

    if (results.length === 0) {
      return new Response('Resource not found', { status: 404 });
    }

    const url = results[0].url;
    const key = url.replace('https://files.danieltesting.space/', '');

    // Delete file from R2
    await env.MY_BUCKET.delete(key);

    // Delete DB row
    await env.DB.prepare(`DELETE FROM resources WHERE id = ?`).bind(id).run();

    return new Response('Deleted', { status: 200 });

  } catch (err) {
    console.error('Failed to delete resource:', err);
    return new Response('Delete failed', { status: 500 });
  }
}
