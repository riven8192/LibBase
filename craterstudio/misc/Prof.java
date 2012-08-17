/*
 * Created on Aug 12, 2009
 */

package craterstudio.misc;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import craterstudio.text.Text;
import craterstudio.text.TextDateTime;
import craterstudio.text.TextValues;
import craterstudio.time.Interval;
import craterstudio.util.HighLevel;

public class Prof
{
   static final Map<String, TaskProfiler> id2prof;
   static final Map<String, Long>         id2last;

   static
   {
      id2prof = new HashMap<String, TaskProfiler>();
      id2last = new HashMap<String, Long>();
   }

   public static void startPrinter(long interval)
   {
      final Interval i = new Interval(interval);

      new Thread(new Runnable()
      {
         @Override
         public void run()
         {
            int counter = 0;

            while (true)
            {
               HighLevel.sleep(10);

               if (!i.hasPassedAndStep())
               {
                  continue;
               }

               counter++;

               System.out.println();
               System.out.println("Profiler dump #" + counter + " [" + TextDateTime.now() + "]");

               for (Entry<String, Long> entry : total().entrySet())
               {
                  Long last = id2last.get(entry.getKey());
                  Long curr = entry.getValue();
                  long diff = curr.longValue() - (last == null ? 0L : last.longValue());

                  id2last.put(entry.getKey(), entry.getValue());

                  String currRatio = TextValues.formatNumber(((diff / 1000000L) / (float) i.getInterval() * 100), 1);
                  String avrgRatio = TextValues.formatNumber(((curr.longValue() / 1000000L) / (float) (counter * i.getInterval()) * 100), 1);

                  String k = entry.getKey();
                  String a1 = (diff / 1000000L) + "ms";
                  String b1 = (curr.longValue() / counter / 1000000L) + "ms";
                  String a2 = "(" + currRatio + "%)";
                  String b2 = "(" + avrgRatio + "%)";

                  k = Text.formatString(k, 40, Text.ALIGN_LEFT, ' ');
                  a1 = Text.formatString(a1, 8, Text.ALIGN_RIGHT, ' ');
                  b1 = Text.formatString(b1, 8, Text.ALIGN_RIGHT, ' ');
                  a2 = Text.formatString(a2, 8, Text.ALIGN_RIGHT, ' ');
                  b2 = Text.formatString(b2, 8, Text.ALIGN_RIGHT, ' ');

                  System.out.println("\t " + k + " => " + a1 + a2 + " " + b1 + b2);
               }
            }
         }
      }).start();
   }

   public static void start(String id)
   {
      synchronized (id2prof)
      {
         TaskProfiler prof = id2prof.get(id);
         if (prof == null)
            id2prof.put(id, prof = new TaskProfiler());
         prof.start();
      }
   }

   public static void stop(String id)
   {
      synchronized (id2prof)
      {
         TaskProfiler prof = id2prof.get(id);
         if (prof == null)
            id2prof.put(id, prof = new TaskProfiler());
         prof.stop();
      }
   }

   public static Map<String, Long> total()
   {
      Map<String, Long> map = new HashMap<String, Long>();

      synchronized (id2prof)
      {
         for (Entry<String, TaskProfiler> entry : id2prof.entrySet())
         {
            map.put(entry.getKey(), Long.valueOf(entry.getValue().total()));
         }
      }

      return map;
   }
}