import { verify } from 'hono/jwt'; // or use your JWT lib

async function isAuthorized(request, env) {
  const auth = request.headers.get('authorization');
  if (!auth || !auth.startsWith('Bearer ')) return false;

  const token = auth.split(' ')[1];
  try {
    const payload = await verify(token, env.JWT_SECRET);
    return payload.role === 'admin'; // customize as needed
  } catch {
    return false;
  }
}

export async function onRequestDelete({ request, env, params }) {
  if (!(await isAuthorized(request, env))) {
    return new Response('Unauthorized', { status: 401 });
  }

  const id = params.id;
  if (!id) return new Response('Missing ID', { status: 400 });

  try {
    const { results } = await env.DB.prepare(
      `SELECT url FROM resources WHERE id = ?`
    ).bind(id).all();

    if (results.length === 0) {
      return new Response('Resource not found', { status: 404 });
    }

    const key = results[0].url.replace('https://files.danieltesting.space/', '');
    await env.MY_BUCKET.delete(key);
    await env.DB.prepare(`DELETE FROM resources WHERE id = ?`).bind(id).run();

    return new Response('Deleted', { status: 200 });
  } catch (err) {
    console.error('Failed to delete resource:', err);
    return new Response('Delete failed', { status: 500 });
  }
}