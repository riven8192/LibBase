/*
 * Created on 8 jun 2010
 */

package craterstudio.time;

import craterstudio.text.TextDate;

public class YearMonthDate
{
   public int year;
   public int month;
   public int date;

   public YearMonthDate()
   {
      //
   }

   public YearMonthDate(String yyyy_mm_dd)
   {
      this.year = TextDate.year(yyyy_mm_dd);
      this.month = TextDate.month(yyyy_mm_dd);
      this.date = TextDate.day(yyyy_mm_dd);
   }

   public YearMonthDate(int year, int month, int date)
   {
      this.year = year;
      this.month = month;
      this.date = date;
   }

   YearMonthDate load(YearMonthDate that)
   {
      this.year = that.year;
      this.month = that.month;
      this.date = that.date;
      return this;
   }

   @Override
   public String toString()
   {
      return TextDate.set(this.year, this.month, this.date);
   }
}