/*
 * Created on 3 jan 2011
 */

package craterstudio.time;

import java.util.ArrayList;
import java.util.List;


import craterstudio.text.TextDate;
import craterstudio.util.ListUtil;

public class DateInterval
{
   public String           begin_date;
   public String           end_date;

   public int              max_matches;
   public int              interval_amount;
   public DateIntervalType interval_type;

   public void setup(String begin, int limit)
   {
      this.begin_date = begin;
      this.end_date = null;
      this.max_matches = limit;
   }

   public void setup(String begin, String end)
   {
      this.begin_date = begin;
      this.end_date = end;
      this.max_matches = 0;
   }

   public void interval(int interval, DateIntervalType type)
   {
      this.interval_amount = interval;
      this.interval_type = type;
   }

   //

   public void verifyState()
   {
      if (this.interval_amount <= 0 || this.interval_type == null)
      {
         throw new IllegalStateException("incorrect interval: " + this.interval_amount + " " + this.interval_type);
      }

      if (this.end_date == null)
      {
         if (this.max_matches <= 0)
            throw new IllegalStateException("incorrect end condition: " + this.max_matches + " matches");
         TextDate.check(this.begin_date);
      }
      else
      {
         if (this.max_matches != 0)
            throw new IllegalStateException("incorrect end condition: " + this.max_matches + " matches");
         if (!TextDate.lessThanOrEquals(this.begin_date, this.end_date))
            throw new IllegalStateException("begin > end");
      }
   }

   public String[] getMatches()
   {
      YearMonthDate begin = new YearMonthDate(this.begin_date);

      YearMonthDate end = null;
      if (this.end_date != null)
      {
         end = new YearMonthDate(this.end_date);
         if (DateMath.compare(begin, end) > 0)
            throw new IllegalStateException();
      }

      List<String> matches = new ArrayList<String>();

      for (int traverse = 0; true; traverse += this.interval_amount)
      {
         YearMonthDate result = new YearMonthDate();

         switch (this.interval_type)
         {
            case DAY:
               DateMath.traverseDays(begin, traverse, result);
               break;

            case MONTH:
               DateMath.traverseMonths(begin, traverse, result);
               break;

            case YEAR:
               DateMath.traverseYears(begin, traverse, result);
               break;

            default:
               throw new IllegalStateException();
         }

         // too late
         if (this.end_date != null && DateMath.compare(result, end) > 0)
            break;

         matches.add(result.toString());

         // enough matches
         if (this.end_date == null && matches.size() == this.max_matches)
            break;
      }

      return ListUtil.toArray(String.class, matches);
   }
}
