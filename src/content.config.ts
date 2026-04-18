import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'zod';

const posts = defineCollection({
  loader: glob({ pattern: '**/*.mdx', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    draft: z.boolean().optional(),
  }),
});

const gallery = defineCollection({
  loader: glob({ pattern: '**/*.yaml', base: './src/content/gallery' }),
  schema: ({ image }) =>
    z.object({
      title: z.string(),
      subtitle: z.string(),
      description: z.string(),
      paintings: z.array(
        z.object({
          number: z.string(),
          section: z.string().optional(),
          title: z.string(),
          meta: z.string(),
          image: image(),
          alt: z.string(),
          description: z.string(),
          chiaroscuroNote: z.string(),
          descriptionEnd: z.string(),
        }),
      ),
      sources: z
        .array(
          z.object({
            name: z.string(),
            url: z.url(),
          }),
        )
        .optional(),
    }),
});

export const collections = { posts, gallery };
