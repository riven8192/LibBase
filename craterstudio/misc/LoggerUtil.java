/*
 * Created on 12 feb 2010
 */

package craterstudio.misc;

import java.io.OutputStream;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.StreamHandler;

public class LoggerUtil
{
   public static Logger global()
   {
      return Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
   }

   public static void attachOutputStreamHandler(Level level, OutputStream out)
   {
      attachOutputStreamHandler(Logger.GLOBAL_LOGGER_NAME, level, out);
   }

   public static void attachOutputStreamHandler(String name, Level level, OutputStream out)
   {
      attachOutputStreamHandler(Logger.getLogger(name), level, out);
   }

   public static void attachOutputStreamHandler(Logger logger, Level level, OutputStream out)
   {
      Formatter formatter = new Formatter()
      {
         @Override
         public String format(LogRecord record)
         {
            return record.getLevel().getName() + ": " + record.getMessage() + "\r\n";
         }
      };

      Handler stdout = new StreamHandler(out, formatter)
      {
         @Override
         public synchronized void publish(LogRecord record)
         {
            super.publish(record);

            this.flush();
         }
      };
      stdout.setLevel(level);

      logger.addHandler(stdout);
   }
}
