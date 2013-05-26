/*
 * Created on 19-sep-2007
 */

package craterstudio.bytes;


class PageBlock
{
   private final Thread access;
   private final long   base;
   private final Page[] pages;
   private final int[]  usage;

   public PageBlock(int pages)
   {
      this.access = Thread.currentThread();

      this.base = NativeAllocator.malloc_page(pages);
      long size = NativeAllocator.pageSize();

      this.pages = new Page[pages];
      this.usage = new int[pages];

      for (int i = 0; i < pages; i++)
         this.pages[i] = new Page(base + i * size);
   }

   private int lastNew = 0;

   public Page usePage()
   {
      this.checkAccess();

      for (int i = 0; i < pages.length; i++)
      {
         int k = (lastNew + i) % pages.length;
         Page p = pages[k];
         if (usage[k] == 0)
         {
            usage[k] = 1;
            lastNew = k;
            return p;
         }
      }

      throw new IllegalStateException("no page available");
   }

   public void freePage(Page page)
   {
      this.checkAccess();

      for (int i = 0; i < pages.length; i++)
      {
         Page p = pages[i];
         if (p != page)
            continue;

         if (usage[i] == 0)
            throw new IllegalStateException("page already free");
         usage[i] = 0;
         return;
      }

      throw new IllegalStateException("page not in block");
   }

   private boolean disposed = false;

   public void dispose()
   {
      this.checkAccess();

      for (int i = 0; i < pages.length; i++)
         if (usage[i] != 0)
            throw new IllegalStateException("cannot dispose, used page found");

      NativeAllocator.free(base);
      disposed = true;
   }

   private final void checkAccess()
   {
      if (access != Thread.currentThread())
         throw new IllegalStateException("block may only be accessed from the thread that created it");
      if (disposed)
         throw new IllegalStateException("block already disposed");
   }
}