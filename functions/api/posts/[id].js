export async function onRequest({ request, env, params }) {
  if (request.method !== 'DELETE') {
    return new Response('Method Not Allowed', { status: 405 });
  }
  await env.POSTS_DB
    .prepare(`DELETE FROM posts WHERE id = ?`)
    .bind(params.id)
    .run();
  return new Response(null, { status: 204 });
}