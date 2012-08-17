/*
 * Created on 30 dec 2008
 */

package craterstudio.io;

import java.io.PrintStream;
import java.util.Calendar;

public class Logger
{
   public static final int    INFO         = 0;
   public static final int    NOTIFICATION = 1;
   public static final int    WARNING      = 2;
   public static final int    ERROR        = 3;
   public static final int    FAILURE      = 4;

   private static PrintStream out;
   private static int         callee_stack_depth;
   private static int         verbose_level;

   static
   {
      out = System.out;
      callee_stack_depth = 2;
      verbose_level = INFO;
   }

   public static void setDefaultVerboseLevel(int level)
   {
      verbose_level = level;
   }

   public static void setOut(PrintStream out)
   {
      Logger.out = out;
   }

   public synchronized static void currentLocationInfo()
   {
      callee_stack_depth += 1;
      info("");
      callee_stack_depth -= 1;
   }

   public synchronized static void info(String format, Object... args)
   {
      if (verbose_level <= INFO)
         out.printf(prefix(INFO) + format + "\n", args);
   }

   public synchronized static void notification(String format, Object... args)
   {
      if (verbose_level <= NOTIFICATION)

         out.printf(prefix(NOTIFICATION) + format + "\n", args);
   }

   public synchronized static void warning(String format, Object... args)
   {
      if (verbose_level <= WARNING)

         out.printf(prefix(WARNING) + format + "\n", args);
   }

   public synchronized static void error(String format, Throwable exc, Object... args)
   {
      if (verbose_level <= ERROR)
      {
         out.printf(prefix(ERROR) + format + "\n", args);
         exc.printStackTrace(out);
      }
   }

   public synchronized static void failure(String format, Throwable t, Object... args)
   {
      if (verbose_level <= FAILURE)
      {
         out.printf(prefix(FAILURE) + format + "\n", args);
         t.printStackTrace(out);
      }
   }

   private static String prefix(int level)
   {
      String name;
      switch (level)
      {
         case INFO:
            name = "INFO";
            break;
         case NOTIFICATION:
            name = "NOTI";
            break;
         case WARNING:
            name = "WARN";
            break;
         case ERROR:
            name = "ERRR";
            break;
         case FAILURE:
            name = "FAIL";
            break;
         default:
            throw new IllegalArgumentException();
      }

      final String from;
      {
         StackTraceElement elem = new Throwable().getStackTrace()[callee_stack_depth];
         String classname = elem.getClassName();
         classname = classname.substring(classname.lastIndexOf('.') + 1);
         from = " " + classname + "." + elem.getMethodName() + "()";
      }

      final String now;
      {
         Calendar c = Calendar.getInstance();
         String shh = double_digits[c.get(Calendar.HOUR_OF_DAY)];
         String smm = double_digits[c.get(Calendar.MINUTE)];
         String sss = double_digits[c.get(Calendar.SECOND)];
         now = shh + ":" + smm + ":" + sss;
      }

      return "[" + name + " " + now + from + "] ";
   }

   static final String[] double_digits;

   static
   {
      double_digits = new String[100];
      for (int i = 0; i < double_digits.length; i++)
         double_digits[i] = (i < 10 ? "0" : "") + i;
   }
}