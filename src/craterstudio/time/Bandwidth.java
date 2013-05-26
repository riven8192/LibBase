/*
 * Created on 1 jun 2010
 */

package craterstudio.time;

import java.util.concurrent.atomic.AtomicLong;

import craterstudio.text.TextValues;

public class Bandwidth
{
   private final Interval   oneSecond;
   private final AtomicLong trafficSecond;

   public Bandwidth()
   {
      this.oneSecond = new Interval(1000L);
      this.trafficSecond = new AtomicLong();
   }

   protected void log(long bandwidth)
   {
      String formatted = TextValues.formatWithMagnitudeBytes(bandwidth, 1);
      System.out.println("bandwidth: " + formatted + "B");
   }

   public void traffic(int bytes)
   {
      long bandwidth = this.trafficSecond.addAndGet(bytes);

      if (this.oneSecond.hasPassedAndStep())
      {
         this.trafficSecond.addAndGet(-bandwidth);

         this.log(bandwidth);
      }
   }
}
