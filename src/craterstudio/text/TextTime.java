/*
 * Created on 12 sep 2008
 */

package craterstudio.text;

import java.util.Calendar;

import craterstudio.math.EasyMath;

public class TextTime
{
   public static String set(int h, int m, int s)
   {
      //String hh = ((h < 10) ? "0" : "") + h;
      //String mm = ((m < 10) ? "0" : "") + m;
      //String ss = ((s < 10) ? "0" : "") + s;
      //return hh + ":" + mm + ":" + ss;

      StringBuilder sb = new StringBuilder(8);
      if (h < 10)
         sb.append('0');
      sb.append(h);
      sb.append(':');
      if (m < 10)
         sb.append('0');
      sb.append(m);
      sb.append(':');
      if (s < 10)
         sb.append('0');
      sb.append(s);
      return sb.toString();
   }

   public static boolean equals(String a, String b)
   {
      return TextTime.compare(a, b) == 0;
   }

   public static boolean lessThan(String a, String b)
   {
      return TextTime.compare(a, b) < 0;
   }

   public static boolean greaterThan(String a, String b)
   {
      return TextTime.compare(a, b) > 0;
   }

   public static boolean lessThanOrEquals(String a, String b)
   {
      return TextTime.compare(a, b) <= 0;
   }

   public static boolean moreThanOrEquals(String a, String b)
   {
      return TextTime.compare(a, b) >= 0;
   }

   public static boolean between(String s, String lo, String hi)
   {
      return TextTime.moreThanOrEquals(s, lo) && TextTime.lessThanOrEquals(s, hi);
   }

   public static int diffInSec(String from, String until)
   {
      return timeToSec(until) - timeToSec(from);
   }

   //

   public static int hour(String ss)
   {
      return Integer.parseInt(ss.substring(0, 2));
   }

   public static int minute(String ss)
   {
      return Integer.parseInt(ss.substring(3, 5));
   }

   public static int second(String ss)
   {
      return Integer.parseInt(ss.substring(6, 8));
   }

   public static int timeToSec(String ss)
   {
      return hour(ss) * 3600 + minute(ss) * 60 + second(ss);
   }

   public static String millisToTime(long millis)
   {
      return secToTime((int) (millis / 1000));
   }

   public static String secToTime(int sec)
   {
      if (sec < 0)
         throw new IllegalArgumentException();

      int h = (sec / 3600) % 24;
      int m = (sec % 3600) / 60;
      int s = sec % 60;
      return TextTime.set(h, m, s);
   }

   public static String now()
   {
      return TextTime.fromCalendar(Calendar.getInstance());
   }

   public static String traverseSeconds(String ss, int seconds)
   {
      seconds %= 60 * 60 * 24;

      Calendar c = TextTime.toCalendar(ss);
      c.setTimeInMillis(c.getTimeInMillis() + (1000L * seconds));
      return TextTime.fromCalendar(c);
   }

   public static Calendar toCalendar(String ss)
   {
      TextTime.check(ss);

      Calendar c = Calendar.getInstance();
      c.set(Calendar.HOUR_OF_DAY, hour(ss));
      c.set(Calendar.MINUTE, minute(ss));
      c.set(Calendar.SECOND, second(ss));
      return c;
   }

   public static String fromCalendar(Calendar c)
   {
      int hh = c.get(Calendar.HOUR_OF_DAY);
      int mm = c.get(Calendar.MINUTE);
      int ss = c.get(Calendar.SECOND);
      return ((hh < 10) ? "0" : "") + hh + ":" + ((mm < 10) ? "0" : "") + mm + ":" + ((ss < 10) ? "0" : "") + ss;
   }

   public static boolean is(String s)
   {
      // HH:MM:SS
      if (s.length() != 8)
         return false;
      if (s.charAt(2) != ':')
         return false;
      if (s.charAt(5) != ':')
         return false;

      int hh, mm, ss;

      try
      {
         hh = Integer.parseInt(s.substring(0, 2));
         mm = Integer.parseInt(s.substring(3, 5));
         ss = Integer.parseInt(s.substring(6, 8));
      }
      catch (NumberFormatException exc)
      {
         return false;
      }

      if (EasyMath.isBetween(hh, 0, 23))
         if (EasyMath.isBetween(mm, 0, 59))
            if (EasyMath.isBetween(ss, 0, 59))
               return true;

      return false;
   }

   public static String check(String s)
   {
      if (!TextTime.is(s))
      {
         if (s.length() == 10)
            throw new IllegalArgumentException("probably a DATE instead of TIME: '" + s + "'");
         if (s.length() == 19)
            throw new IllegalArgumentException("probably a DATETIME instead of TIME: '" + s + "'");
         throw new IllegalArgumentException(s);
      }
      return s;
   }

   public static int compare(String a, String b)
   {
      TextTime.check(a);
      TextTime.check(b);

      int diff;
      for (int i = 0; i < 8; i++)
         if ((diff = a.charAt(i) - b.charAt(i)) != 0)
            return diff;
      return 0;
   }
}
