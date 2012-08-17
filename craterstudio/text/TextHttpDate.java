/*
 * Created on Jun 16, 2009
 */

package craterstudio.text;

import java.util.Calendar;
import java.util.TimeZone;

public class TextHttpDate
{
   static long   cached_now;
   static String cached_date;

   public static String now()
   {
      long now = System.currentTimeMillis() / 1000;
      if (now != cached_now)
      {
         cached_now = now;
         cached_date = TextHttpDate.exportGMT(System.currentTimeMillis());
      }
      return cached_date;
   }

   public static String exportGMT(long millis)
   {
      return exportForTimezone(millis, "GMT");
   }

   public static String exportForTimezone(long millis, String timezone)
   {
      // Dow, DD Mon YYYY 00:00:00 GMT

      Calendar cal = Calendar.getInstance();
      cal.setTimeInMillis(millis);
      cal.setTimeZone(TimeZone.getTimeZone(timezone));

      String s = DAY_OF_WEEK[cal.get(Calendar.DAY_OF_WEEK) - Calendar.SUNDAY];
      s += ", " + cal.get(Calendar.DAY_OF_MONTH);
      s += " " + MONTH_OF_YEAR[cal.get(Calendar.MONTH)];
      s += " " + cal.get(Calendar.YEAR);
      s += " " + TextTime.fromCalendar(cal);
      s += " " + timezone;
      return s;
   }

   public static String toDateTime(String httpDate)
   {
      // Dow, DD Mon YYYY 00:00:00 GMT
      // Dow, DD Mon YYYY 00:00:00 +0230
      String[] parts = Text.split(httpDate, ' ');
      int dd = Integer.parseInt(parts[1]);
      int mm = -1;
      for (int i = 0; i < MONTH_OF_YEAR.length; i++)
         if (parts[2].equalsIgnoreCase(MONTH_OF_YEAR[i]))
            mm = i + 1;
      int yyyy = Integer.parseInt(parts[3]);

      // X:X:X -> XX:XX:XX
      String time = parts[4];
      if (time.length() != 8)
      {
         String[] time_ = Text.split(time, ':');
         for (int i = 0; i < 3; i++)
            if (time_[i].length() == 1)
               time_[i] = "0" + time_[i];
         time = TextTime.check(Text.join(time_, ':'));
      }
      String datetime = TextDate.set(yyyy, mm, dd) + ' ' + time;

      // GMT or +0230 or -0230
      if (parts.length > 5)
      {
         if (parts[5].startsWith("+"))
            parts[5] = parts[5].substring(1);

         int hhmm = TextValues.tryParseInt(parts[5], 0);
         boolean neg = hhmm < 0;
         hhmm = Math.abs(hhmm);
         int hh_ = hhmm / 100;
         int mm_ = hhmm % 100;
         int diff = ((hh_ * 60) + mm_) * (neg ? -1 : +1);
         datetime = TextDateTime.traverseSeconds(datetime, diff);
      }

      return datetime;
   }

   public static long fromHttpDate(String httpDate)
   {
      try
      {
         String datetime = toDateTime(httpDate);
         Calendar c = TextDateTime.toCalendar(datetime);
         return c.getTimeInMillis() + c.get(Calendar.ZONE_OFFSET) + c.get(Calendar.DST_OFFSET);
      }
      catch (Exception exc)
      {
         throw new IllegalStateException("illegal httpdate: [" + httpDate + "]");
      }
   }

   public static int[]    DAYS_IN_MONTH = new int[] { 31, -1, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
   public static String[] DAY_OF_WEEK   = new String[] { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
   public static String[] MONTH_OF_YEAR = new String[] { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
}
