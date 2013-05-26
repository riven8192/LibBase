/*
 * Created on 10 mei 2010
 */

package craterstudio.time;

import craterstudio.text.TextDateTime;
import craterstudio.util.HighLevel;

public class SnappedInterval
{
   public static void main(String[] args)
   {
      SnappedInterval si = new SnappedInterval(20 * SECOND);

      while (true)
      {
         System.out.println(TextDateTime.now());
         if (si.step())
            System.out.println("---");
         HighLevel.sleep(1000);
      }
   }

   public static final long SECOND = 1000L;
   public static final long MINUTE = SECOND * 60L;
   public static final long HOUR   = MINUTE * 60L;
   public static final long DAY    = HOUR * 24L;
   public static final long WEEK   = DAY * 7;

   private long             last;
   private long             duration;

   public SnappedInterval(long duration)
   {
      this.duration = duration;
      this.last = this.current();
   }

   private final long current()
   {
      return System.currentTimeMillis() / this.duration;
   }

   public boolean consume()
   {
      long c = this.current();
      if (c == this.last)
         return false;
      this.last = c;
      return true;
   }

   public boolean step()
   {
      if (this.current() == this.last)
      {
         return false;
      }
      this.last += 1;
      return true;
   }
}
