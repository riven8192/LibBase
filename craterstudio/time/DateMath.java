/*
 * Created on 21 mei 2010
 */

package craterstudio.time;

import java.util.Calendar;

import craterstudio.text.TextDate;

public class DateMath
{
   public static void main(String[] args)
   {
      final int min = 1970;
      final int max = 2100;

      Calendar c = Calendar.getInstance();
      c.set(min, 0, 1, 0, 0, 0);

      int errors = 0;
      outer: while (true)
      {
         c.add(Calendar.DATE, 1);
         int yyyy = c.get(Calendar.YEAR);
         int mm = c.get(Calendar.MONTH) + 1;
         int dd = c.get(Calendar.DAY_OF_MONTH);

         if (yyyy >= max)
            break outer;

         int woy1 = c.get(Calendar.WEEK_OF_YEAR);
         int woy2 = DateMath.getWeekOfYear(yyyy, mm, dd);

         if (woy1 != woy2)
         {
            System.out.println(TextDate.set(yyyy, mm, dd) + " =" + (woy1 - woy2) + " [" + (c.get(Calendar.DAY_OF_WEEK) - Calendar.SUNDAY) + "] calendar=" + woy1 + " <> datemath=" + woy2 + " [" + DateMath.getDayOfWeek(yyyy, mm, dd) + "]");
            errors++;
         }
      }

      for (int y = min; y <= max; y++)
         System.out.println(y + " => " + DateMath.getDayOfWeek(y, 1, 1));

      System.out.println(errors);
   }

   public static YearMonthDate nextDay(YearMonthDate result)
   {
      // less than 28 feb
      if (result.date < 28 || result.date < getDaysInMonth(result.year, result.month))
      {
         result.date += 1;
         return result;
      }

      result.date = 1;

      if (result.month == 12)
      {
         result.month = 1;
         result.year += 1;
      }
      else
      {
         result.month += 1;
      }

      return result;
   }

   public static YearMonthDate nextMonth(YearMonthDate result)
   {
      if (result.month == 12)
      {
         result.month = 1;
         result.year++;
      }
      else
      {
         result.month++;
      }

      int max = DateMath.getDaysInMonth(result.year, result.month);
      if (result.date > max)
         result.date = max;

      return result;
   }

   public static YearMonthDate nextDay(YearMonthDate from, YearMonthDate result)
   {
      return nextDay(result.load(from));
   }

   public static YearMonthDate nextMonth(YearMonthDate from, YearMonthDate result)
   {
      return nextMonth(result.load(from));
   }

   public static YearMonthDate previousDay(YearMonthDate from, YearMonthDate result)
   {
      if (from.date == 1)
      {
         if (from.month == 1)
         {
            result.year = from.year - 1;
            result.month = 12;
            result.date = 31;
         }
         else
         {
            result.year = from.year;
            result.month = from.month - 1;
            result.date = getDaysInMonth(result.year, result.month);
         }
      }
      else
      {
         result.year = from.year;
         result.month = from.month;
         result.date -= 1;
      }

      return result;
   }

   public static YearMonthDate traverse(DateIntervalType type, YearMonthDate from, int amount, YearMonthDate result)
   {
      switch (type)
      {
         case YEAR:
            return traverseYears(from, amount, result);
            
         case MONTH:
            return traverseMonths(from, amount, result);
            
         case WEEK:
            return traverseDays(from, amount * 7, result);
            
         case DAY:
            return traverseDays(from, amount, result);
            
         default:
            throw new UnsupportedOperationException();
      }
   }

   public static YearMonthDate traverseDays(YearMonthDate from, int traverseDays, YearMonthDate result)
   {
      if (traverseDays == 0)
         return result.load(from);
      if (traverseDays == 1)
         return nextDay(from, result);
      int dayOffset = daysSinceEpoch(from.year, from.month, from.date);
      return daysSinceEpochToDate(dayOffset + traverseDays, result);
   }

   public static YearMonthDate traverseMonths(YearMonthDate from, int traverseMonths, YearMonthDate result)
   {
      if (traverseMonths == 0)
         return result.load(from);
      if (traverseMonths == 1)
         return nextMonth(from, result);

      traverseMonths -= 1; // one less month
      result.load(from);
      result.month += traverseMonths;
      {
         if (result.month > 12)
         {
            result.year += (result.month - 1) / 12 + 0;
            result.month = (result.month - 1) % 12 + 1;
         }
         else if (result.month < 1)
         {
            result.year += (result.month - 1) / 12 - 1;
            result.month = ((result.month - 1) % 12 + 12) % 12 + 1; // absolute modulo
         }
      }
      return nextMonth(result); // one more month, handles possible days in months
   }

   public static YearMonthDate traverseYears(YearMonthDate from, int traverseYears, YearMonthDate result)
   {
      result.load(from);
      result.year += traverseYears;
      result.date = Math.min(result.date, DateMath.getDaysInMonth(result.year, result.month)); // leap day
      return result;
   }

   public static boolean isBefore(YearMonthDate from, YearMonthDate until)
   {
      return compare(from, until) < 0;
   }

   /**
    * compare(2000/01/01 => 2000/01/01) = 0<br>
    * compare(2000/01/01 => 2000/01/03) = +2<br>
    * compare(2000/01/03 => 2000/01/01) = -2<br>
    */

   public static int compare(YearMonthDate from, YearMonthDate until)
   {
      int since1 = daysSinceEpoch(from.year, from.month, from.date);
      int since2 = daysSinceEpoch(until.year, until.month, until.date);
      return since1 - since2;
   }

   /**
    * duration(2000/01/01 => 2000/01/01) = 1 days<br>
    * duration(2000/01/01 => 2000/01/03) = 3 days<br>
    * duration(2000/01/03 => 2000/01/01) = [exception]<br>
    */

   public static int duration(YearMonthDate from, YearMonthDate until)
   {
      int diff = -compare(from, until);
      if (diff < 0)
         throw new IllegalStateException("from > until");
      return diff + 1;
   }

   /**
    * Sunday = 0<br>
    * Monday = 1<br>
    * Tuesday = 2<br>
    * Wednesday = 3<br>
    * Thursday = 4<br>
    * Friday = 5<br>
    * Saturday = 6 
    */

   public static int getDayOfWeek(int year, int month, int date)
   {
      return (dayOfWeekOnEpoch() + daysSinceEpoch(year, month, date)) % 7;
   }

   public static int getWeekOfYear(int year, int month, int date)
   {
      if (year < 1970 || year > 2100)
         throw new UnsupportedOperationException("1970 <= year <= 2100");

      int dow11 = getDayOfWeek(year, 1, 1);
      int d1 = (dow11 + 7 - 2) % 7;
      int diy = getDayInYear(year, month, date);
      int woy = (diy + d1) / 7 + (d1 < 3 ? 1 : 0);

      if (woy == 0)
      {
         if (month == 1 && date == 1)
         {
            if (d1 == 3)
               woy = 53;
            else if (d1 == 4)
               woy = ((year - 17) % 28 == 0) ? 53 : 52;
            else if (d1 == 5)
               woy = 52;
         }
         else if (dow11 >= 5 && diy >= 2 && diy <= 3)
         {
            woy = (((year - 12) % 28) % 11 == 0) ? 52 : 53;
         }
      }
      else if (woy == 53)
      {
         if ((year - 24) % 28 == 0)
         {
            woy = 1;
         }
         else if (dow11 >= 1 && dow11 <= 3)
         {
            if (((year - 4) % 28) % 20 != 0)
            {
               woy = 1;
            }
         }
      }

      return woy;
   }

   /**
    * Range: 1..{365|366}
    */

   public static int getDayInYear(int year, int month, int date)
   {
      if (month < 3)
         return date + (month - 1) * 31;
      date += daysInFebruary(year);
      date += (month - 2) * 30;
      date += (month + (month >> 3)) >> 1;
      return date;
   }

   public static int getDaysInMonth(int year, int month)
   {
      if (month == 2)
         return daysInFebruary(year);
      return 30 + ((month & 1) ^ (month >> 3));
   }

   public static int getDaysInYear(int year)
   {
      return isLeapYear(year) ? 366 : 365;
   }

   public static boolean isLeapDay(int year, int month, int date)
   {
      return (month == 2) && (date == 29) && isLeapYear(year);
   }

   public static boolean isLeapYear(int year)
   {
      if (year % 100 == 0)
         return (year % 400 == 0);
      return ((year & 3) == 0);
   }

   private static int daysInFebruary(int year)
   {
      return isLeapYear(year) ? 29 : 28;
   }

   private static int dayOfWeekOnEpoch()
   {
      // 1970/01/01 is a Thursday, 4 days after Sunday
      return 4; //Calendar.THURSDAY - Calendar.SUNDAY;
   }

   private static int daysSinceEpoch(int year, int month, int date)
   {
      int epochLeapDays = getLeapDaysInEpoch();
      int pyearLeapDays = getLeapDaysSinceEpochInYear(year - 1);
      int daysInYearsBetween = 365 * (year - 1970);
      daysInYearsBetween += pyearLeapDays - epochLeapDays;
      daysInYearsBetween += getDayInYear(year, month, date);
      return daysInYearsBetween - 1;
   }

   private static YearMonthDate daysSinceEpochToDate(int remainingDays, YearMonthDate result)
   {
      int minYears = remainingDays / 366;
      int totYears = minYears + 1970;
      int minLeapDays = (minYears + (isLeapYear(totYears) ? 1 : 0)) - (getLeapDaysSinceEpochInYear(totYears) - getLeapDaysInEpoch());

      remainingDays -= minYears * 366;
      remainingDays += minLeapDays;

      int year = 1970 + minYears;
      while (true)
      {
         int yearDays = getDaysInYear(year);
         if (remainingDays < yearDays)
            break;
         remainingDays -= yearDays;
         year++;
      }

      int[] lookup = isLeapYear(year) ? lookupLeap : lookupNorm;
      int month; // binary search is slower
      for (month = 1; month <= 12; month++)
         if (remainingDays <= lookup[month])
            break;
      remainingDays -= lookup[month - 1] + 1;

      //

      int date = 1 + remainingDays;

      result.year = year;
      result.month = month;
      result.date = date;

      return result;
   }

   private static int getLeapDaysSinceEpochInYear(int year)
   {
      // return (year / 4) - (year / 100) + (year / 400);
      int century = (year / 100);
      return (year >> 2) - century + (century >> 2);
   }

   private static int getLeapDaysInEpoch()
   {
      // final int year = 1970;
      // return (year / 4) - (year / 100) + (year / 400);
      // return 492 - 19 + 4;
      // return 477;
      return 477;
   }

   private static final int[] lookupNorm = new int[13];
   private static final int[] lookupLeap = new int[13];

   static
   {
      lookupNorm[0] = lookupLeap[0] = -1;
      for (int m = 1; m <= 12; m++)
      {
         lookupNorm[m] = (lookupNorm[m - 1] + getDaysInMonth(1970, m));
         lookupLeap[m] = (lookupLeap[m - 1] + getDaysInMonth(1972, m));
      }
   }
}
