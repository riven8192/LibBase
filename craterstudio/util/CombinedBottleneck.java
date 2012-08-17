/*
 * Created on 7 jun 2010
 */

package craterstudio.util;

import java.util.ArrayList;
import java.util.List;

public class CombinedBottleneck implements Bottleneck
{
   private final List<ThroughputBottleneck> bottlenecks;

   public CombinedBottleneck()
   {
      this.bottlenecks = new ArrayList<ThroughputBottleneck>();
   }

   public void add(ThroughputBottleneck bottleneck)
   {
      this.bottlenecks.add(bottleneck);
   }

   @Override
   public int feed(int amount)
   {
      int[] got = new int[this.bottlenecks.size()];

      int i = 0, min = amount;
      for (ThroughputBottleneck bottleneck : this.bottlenecks)
         min = Math.min(min, got[i++] = bottleneck.feed(min));

      for (int n = 0; n < got.length; i++)
         if (got[i] > min)
            bottlenecks.get(n).cancel(got[i] - min);

      return min;
   }
}