import { getCollection } from 'astro:content';
import type { CollectionEntry } from 'astro:content';

type Post = CollectionEntry<'posts'>;

export function isPublishedPost(entry: Post): boolean {
  if (!import.meta.env.PROD) return true;
  return !entry.data.draft && entry.data.pubDate <= new Date();
}

export async function getVisiblePosts(): Promise<Post[]> {
  const posts = await getCollection('posts', isPublishedPost);
  return posts.sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf());
}
