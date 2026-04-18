import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { getVisiblePosts } from '../lib/posts';

export const prerender = true;

export async function GET(context: APIContext) {
  const posts = await getVisiblePosts();

  return rss({
    title: 'Chiaroscuro Joven',
    description:
      'Writing from Chiaroscuro Joven — notes on art, ideas, and what inspires.',
    site: context.site ?? 'https://chiaroscurojoven.com',
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.pubDate,
      description: post.data.description,
      link: `/blog/${post.id}/`,
    })),
    customData: `<language>en-us</language>`,
  });
}
