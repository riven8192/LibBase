/*
 * Created on 12 sep 2008
 */

package craterstudio.text;

import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import craterstudio.math.EasyMath;
import craterstudio.time.DateMath;
import craterstudio.time.YearMonthDate;

public class TextDate
{
   public static String set(int yyyy, int mm, int dd)
   {
      return yyyy + "-" + ((mm < 10) ? "0" : "") + mm + "-" + ((dd < 10) ? "0" : "") + dd;
   }

   public static String min(Iterable<String> dates)
   {
      String min = null;
      for (String date : dates)
         if (min == null || lessThan(date, min))
            min = date;
      return min;
   }

   public static String max(Iterable<String> dates)
   {
      String max = null;
      for (String date : dates)
         if (max == null || greaterThan(date, max))
            max = date;
      return max;
   }

   public static boolean equals(String a, String b)
   {
      return TextDate.compare(a, b) == 0;
   }

   public static boolean lessThan(String a, String b)
   {
      return TextDate.compare(a, b) < 0;
   }

   public static boolean greaterThan(String a, String b)
   {
      return TextDate.compare(a, b) > 0;
   }

   public static boolean lessThanOrEquals(String a, String b)
   {
      return TextDate.compare(a, b) <= 0;
   }

   public static boolean greaterThanOrEquals(String a, String b)
   {
      return TextDate.compare(a, b) >= 0;
   }

   public static boolean betweenInclusive(String s, String lo, String hi)
   {
      return TextDate.greaterThanOrEquals(s, lo) && TextDate.lessThanOrEquals(s, hi);
   }

   public static boolean betweenExclusive(String s, String lo, String hi)
   {
      return TextDate.greaterThan(s, lo) && TextDate.lessThan(s, hi);
   }

   //

   public static int year(String ss)
   {
      return Integer.parseInt(ss.substring(0, 4));
   }

   public static int month(String ss)
   {
      return Integer.parseInt(ss.substring(5, 7));
   }

   public static int day(String ss)
   {
      return Integer.parseInt(ss.substring(8, 10));
   }

   public static int dayOfWeek(String ss)
   {
      return DateMath.getDayOfWeek(TextDate.year(ss), TextDate.month(ss), TextDate.day(ss));
   }

   public static String now()
   {
      return TextDate.fromCalendar(Calendar.getInstance());
   }

   //

   public static int daySpan(String from, String until)
   {
      return DateMath.duration(new YearMonthDate(from), new YearMonthDate(until));
   }

   public static int diff(String from, String until)
   {
      return DateMath.compare(new YearMonthDate(from), new YearMonthDate(until));
   }

   private static final int[]    period_interval = new int[] { 365, 30, 7, 1, 0 };
   private static final String[] period_name     = new String[] { "year", "month", "week", "day", "today" };
   private static final String[] periods_name    = new String[] { "years", "months", "weeks", "days" };

   public static String relativeDaysToDescription(int days, int maxNames)
   {
      if (days == +1)
         return "tomorrow";
      if (days == 0)
         return "today";
      if (days == -1)
         return "yesterday";
      return daysToDescription(days, maxNames);
   }

   public static String daysToDescription(int days, int maxNames)
   {
      boolean history = days < 0;
      if (history)
         days = -days;

      if (maxNames == 1)
      {
         // if there is only 1 period description AND it is occuring 1 time, pick the next period
         for (int i = 0; i < period_interval.length - 1; i++)
         {
            int periodTimes = days / period_interval[i];
            if (periodTimes == 0 || (periodTimes == 1))// && period_interval[i] > 1 && (days % period_interval[i] < period_interval[i] / 2)))
               continue;
            // periodTimes += Math.min(1, days % period_interval[i]); // round up
            return periodTimes + " " + (periodTimes == 1 ? period_name[i] : periods_name[i]) + (history ? " ago" : "");
         }
      }

      StringBuilder sb = new StringBuilder();

      int counter = 0;

      for (int i = 0; i < period_interval.length - 1; i++)
      {
         int periodTimes = days / period_interval[i];

         if (counter < maxNames && (periodTimes > 0))
         {
            if (counter != 0)
               sb.append(", ");
            sb.append(periodTimes);
            sb.append(" ");
            if (counter == maxNames - 1)
               periodTimes += Math.min(1, days % period_interval[i]); // round up
            sb.append(periodTimes == 1 ? period_name[i] : periods_name[i]);
            counter++;
         }

         days -= periodTimes * period_interval[i];
      }

      if (counter == 0)
         sb.append(period_name[4]);
      if (history)
         sb.append(" ago");
      return sb.toString();
   }

   public static String traverseDays(String ss, int days)
   {
      if (days == 0)
         return ss;
      return DateMath.traverseDays(new YearMonthDate(ss), days, new YearMonthDate()).toString();
   }

   public static Calendar toCalendar(String ss)
   {
      TextDate.check(ss);

      Calendar c = Calendar.getInstance();
      c.clear();
      c.set(year(ss), month(ss) - 1, day(ss), 12, 0, 0);
      return c;
   }

   public static String fromCalendar(Calendar c)
   {
      int yyyy = c.get(Calendar.YEAR);
      int mm = c.get(Calendar.MONTH) + 1;
      int dd = c.get(Calendar.DATE);
      return TextDate.set(yyyy, mm, dd);
   }

   public static boolean is(String s)
   {
      // YYYY-MM-DD
      if (s.length() != 10)
         return false;
      if (!Text.areCharsAt(s, '-', 4, 7))
         return false;

      int yyyy, mm, dd;

      try
      {
         yyyy = Integer.parseInt(s.substring(0, 4));
         mm = Integer.parseInt(s.substring(5, 7));
         dd = Integer.parseInt(s.substring(8, 10));
      }
      catch (NumberFormatException exc)
      {
         return false;
      }

      if (!EasyMath.isBetween(yyyy, 0, 2500))
      {
         return false;
      }

      if (!EasyMath.isBetween(mm, 1, 12))
      {
         return false;
      }

      int daysInMonth = DateMath.getDaysInMonth(yyyy, mm);

      if (!EasyMath.isBetween(dd, 1, daysInMonth))
      {
         System.out.println("oops:" + dd + "/" + daysInMonth + " (" + yyyy + "/" + mm + "/" + dd + ")");
         return false;
      }

      return true;
   }

   private static final String[]            nr_postfixes     = new String[] { "ste", "st", "nd", "rd", "th", "de", "e" };

   private static final String[][]          multi_month_names;
   static
   {
      multi_month_names = new String[2][];
      multi_month_names[0] = new String[] { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
      multi_month_names[1] = new String[] { "jan", "feb", "maa", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec" };
   }

   private final static Set<String>         fuzzy_cache_miss = new HashSet<String>();
   private final static Map<String, String> fuzzy_cache_date = new HashMap<String, String>();
   private static final int                 fuzzy_cache_size = 10 * 365;

   public synchronized static String fuzzyFix(String s)
   {
      String got = fuzzy_cache_date.get(s);
      if (got != null)
         return got;

      if (fuzzy_cache_miss.contains(s))
         return null;

      got = fuzzyFixImpl(s);

      if (got == null)
      {
         fuzzy_cache_miss.add(s);
         if (fuzzy_cache_miss.size() > fuzzy_cache_size)
            fuzzy_cache_miss.clear();
      }
      else
      {
         fuzzy_cache_date.put(s, got);
         if (fuzzy_cache_date.size() > fuzzy_cache_size)
            fuzzy_cache_date.clear();
      }

      return got;
   }

   private static String fuzzyFixImpl(String s)
   {
      if (TextDate.is(s = s.trim()))
         return s;

      if (TextDate.is(s = Text.replace(s, '/', '-')))
         return s;
      if (TextDate.is(s = Text.replace(s, ' ', '-')))
         return s;
      if (TextDate.is(s = Text.replace(s, ',', '-')))
         return s;

      if (TextDate.is(s = Text.removeDuplicates(s, '-')))
         return s;

      String[] vals = Text.split(s, '-');
      if (vals.length != 3)
         return null;

      // "Nov 27th, 2009" 
      // "27 Nov, 2009"

      for (int off = 0; off <= 1; off++)
         for (String postfix : nr_postfixes)
            if (vals[off].endsWith(postfix))
               vals[off] = Text.chopLast(vals[off], postfix.length());

      // find year
      int yearIndex = -1;
      {
         for (int i = 0; i < 3; i++)
         {
            int got = TextValues.tryParseInt(vals[i], -1);
            if (got == -1)
               continue;
            if (!EasyMath.isBetween(got, 1000, 2500))
               continue;
            yearIndex = i;
            break;
         }
         if (yearIndex == -1)
            return null;
      }

      String mm, dd;

      if (yearIndex == 0) // american: YYYY/MM/DD
      {
         mm = vals[1];
         dd = vals[2];
      }
      else if (yearIndex == 1) // ?!
      {
         return null;
      }
      else if (yearIndex == 2) // dutch: DD/MM/YYYY
      {
         mm = vals[1];
         dd = vals[0];
      }
      else
      {
         throw new AssertionError();
      }

      if (dd.length() >= 3)
      {
         // swap: MM DD <-> DD MM
         String tt = dd;
         dd = mm;
         mm = tt;
      }

      {
         vals[0] = vals[yearIndex];
         vals[1] = mm;
         vals[2] = dd;
      }

      outer: for (String[] monthNames : multi_month_names)
      {
         if (vals[1].length() < 3) // month
            continue;

         int monthIndex = 0;
         for (String monthName : monthNames)
         {
            monthIndex++;
            if (vals[1].substring(0, 3).toLowerCase().equals(monthName))
            {
               vals[1] = String.valueOf(monthIndex);
               break outer;
            }
         }
      }

      int[] ints;

      try
      {
         ints = TextValues.parseInts(vals);
      }
      catch (NumberFormatException exc)
      {
         return null;
      }

      return TextDate.set(ints[0], ints[1], ints[2]);
   }

   public static String check(String s)
   {
      if (!TextDate.is(s))
      {
         if (s.length() == 8)
            throw new IllegalArgumentException("probably a TIME instead of DATE: '" + s + "'");
         if (s.length() == 19)
            throw new IllegalArgumentException("probably a DATETIME instead of DATE: '" + s + "'");
         throw new IllegalArgumentException(s);
      }

      return s;
   }

   public static int compare(String a, String b)
   {
      TextDate.check(a);
      TextDate.check(b);

      int diff;
      for (int i = 0; i < 10; i++)
         if ((diff = a.charAt(i) - b.charAt(i)) != 0)
            return diff;
      return 0;
   }

   public static String toAmericanDate(String ss)
   {
      int dd = TextDate.day(ss);
      String d = String.valueOf(dd);
      if (dd >= 11 && dd <= 13)
         d += "th";
      else if (dd % 10 == 1)
         d += "st";
      else if (dd % 10 == 2)
         d += "nd";
      else if (dd % 10 == 3)
         d += "rd";
      else
         d += "th";
      return TextHttpDate.MONTH_OF_YEAR[TextDate.month(ss) - 1] + ", " + d + " " + TextDate.year(ss);
   }
}