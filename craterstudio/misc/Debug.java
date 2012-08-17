/*
 * Created on 17 jan 2011
 */

package craterstudio.misc;

import java.util.Arrays;

import craterstudio.text.Text;
import craterstudio.time.Clock;

public class Debug
{
   public static long log(Object val)
   {
      for (StackTraceElement elem : Thread.currentThread().getStackTrace())
      {
         if (elem.getClassName().equals(Thread.class.getName()))
            continue;
         if (elem.getClassName().equals(Debug.class.getName()))
            continue;

         String link = Text.beforeIfAny(Text.afterLastIfAny(elem.getClassName(), '.'), '$') + ".java:" + elem.getLineNumber();
         String msg = "(" + link + ")" + " ." + elem.getMethodName() + "()" + (val != null ? (": " + val) : "");
         Debug.writeln(msg);
         break;
      }

      return Clock.query();
   }

   //

   public static long log(Object... vals)
   {
      return log(Arrays.toString(vals));
   }

   public static long log(boolean val)
   {
      return Debug.log(Boolean.valueOf(val));
   }

   public static long log(int val)
   {
      return Debug.log(Integer.valueOf(val));
   }

   public static long log(long val)
   {
      return Debug.log(Long.valueOf(val));
   }

   public static long log(float val)
   {
      return Debug.log(Float.valueOf(val));
   }

   public static long log(double val)
   {
      return Debug.log(Double.valueOf(val));
   }

   //

   public static long log()
   {
      return log((Object) null);
   }

   public static long log(String key, boolean val)
   {
      return Debug.log(key, Boolean.valueOf(val));
   }

   public static long log(String key, int val)
   {
      return Debug.log(key, Integer.valueOf(val));
   }

   public static long log(String key, long val)
   {
      return Debug.log(key, Long.valueOf(val));
   }

   public static long log(String key, float val)
   {
      return Debug.log(key, Float.valueOf(val));
   }

   public static long log(String key, double val)
   {
      return Debug.log(key, Double.valueOf(val));
   }

   public static long log(String key, Object val)
   {
      return Debug.log(key + "=\'" + val + "\'");
   }

   //

   public static void writeln(String msg)
   {
      System.out.println(msg);
   }
}
