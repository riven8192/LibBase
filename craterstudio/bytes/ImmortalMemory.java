/*
 * Created on 8 jul 2008
 */

package craterstudio.bytes;

public class ImmortalMemory extends ThreadLocal<ImmortalMemory>
{
   @Override
   protected ImmortalMemory initialValue()
   {
      return new ImmortalMemory();
   }

   private static final ImmortalMemory im = new ImmortalMemory();

   public static ImmortalMemory instance()
   {
      return im.get();
   }

   public static long malloc(int bytes)
   {
      return instance().take(bytes);
   }

   private long             pntr, rem;

   private static final int default_malloc_size = 1024 * 1024;

   public long take(long bytes)
   {
      if (bytes > this.rem)
      {
         this.rem = Math.min(default_malloc_size, bytes);
         this.pntr = NativeAllocator.malloc(this.rem);
      }

      long pntr = this.pntr;
      for (long i = 0; i < bytes; i++)
         Native.bput(pntr + i, (byte) 0);

      this.rem -= bytes;
      this.pntr += bytes;

      return pntr;
   }
}
