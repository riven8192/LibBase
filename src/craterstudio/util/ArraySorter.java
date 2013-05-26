/*
 * Created on 15-mei-2005
 */
package craterstudio.util;

public class ArraySorter
{
   public static final void sort(Sortable[] p, int off, int len)
   {
      // pre calculate the sort indices
      for (int i = 0; i < len; i++)
         p[off + i].calcSortIndex();
      ArraySorter.sortImpl(p, off, len);
   }

   static final void sortImpl(Sortable[] p, int off, int len)
   {
      if (len < 7)
      {
         for (int i = off; i < len + off; i++)
            for (int j = i; j > off && p[j - 1].getSortIndex() > p[j].getSortIndex(); j--)
               swap(p, j, j - 1);

         return;
      }

      int m = off + (len >> 1);

      if (len > 7)
      {
         int l = off;
         int n = off + len - 1;

         if (len > 40)
         {
            int s = len >>> 3;
            l = med3(p, l, l + s, l + 2 * s);
            m = med3(p, m - s, m, m + s);
            n = med3(p, n - 2 * s, n - s, n);
         }

         m = med3(p, l, m, n);
      }

      int v = p[m].getSortIndex();

      int a = off;
      int b = a;
      int c = off + len - 1;
      int d = c;

      while (true)
      {
         while (b <= c && p[b].getSortIndex() <= v)
         {
            if (p[b].getSortIndex() == v)
               swap(p, a++, b);
            b++;
         }

         while (c >= b && p[c].getSortIndex() >= v)
         {
            if (p[c].getSortIndex() == v)
               swap(p, c, d--);
            c--;
         }

         if (b > c)
            break;

         swap(p, b++, c--);
      }

      int s, n = off + len;
      s = Math.min(a - off, b - a);
      swapRange(p, off, b - s, s);
      s = Math.min(d - c, n - d - 1);
      swapRange(p, b, n - s, s);

      if ((s = b - a) > 1)
         sortImpl(p, off, s);

      if ((s = d - c) > 1)
         sortImpl(p, n - s, s);
   }

   private static final void swap(Sortable[] p, int a, int b)
   {
      Sortable q = p[a];
      p[a] = p[b];
      p[b] = q;
   }

   private static final void swapRange(Sortable[] p, int a, int b, int n)
   {
      Sortable q;

      for (int i = 0; i < n; i++, a++, b++)
      {
         q = p[a];
         p[a] = p[b];
         p[b] = q;
      }
   }

   private static final int med3(Sortable[] p, int a, int b, int c)
   {
      int a0 = p[a].getSortIndex();
      int b0 = p[b].getSortIndex();
      int c0 = p[c].getSortIndex();
      return (a0 < b0 ? (b0 < c0 ? b : (a0 < c0 ? c : a)) : (b0 > c0 ? b : (a0 > c0 ? c : a)));
   }
}