/*
 * Created on 20 jul 2010
 */

package craterstudio.func;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FunctionalTest
{
   public static void main(String[] args)
   {
      testFilterAndConsume();
   }

   private static void testFilterAndConsume()
   {
      Filter<Integer> evenNumbers = new Filter<Integer>()
      {
         @Override
         public boolean accept(Integer item)
         {
            int value = item.intValue();

            return value % 2 == 0;
         }
      };

      List<Integer> list = intsToList(5, 6, 7, 8, 9);
      System.out.println("list: " + Arrays.toString(iterableToInts(list)));

      int[] result1 = iterableToInts(Functional.filter(list, evenNumbers));
      System.out.println("even=" + Arrays.toString(result1));
      System.out.println("remaining (all): " + Arrays.toString(iterableToInts(list)));

      int[] result2 = iterableToInts(Functional.consume(Functional.filter(list, evenNumbers)));
      System.out.println("even=" + Arrays.toString(result2));
      System.out.println("remaining (odd): " + Arrays.toString(iterableToInts(list)));
   }

   private static final List<Integer> intsToList(int... values)
   {
      List<Integer> list = new ArrayList<Integer>();
      for (int value : values)
         list.add(Integer.valueOf(value));
      return list;
   }

   private static final int[] iterableToInts(Iterable<Integer> list)
   {
      int[] array = new int[4];
      int p = 0;
      for (Integer value : list)
      {
         if (p == array.length)
            array = Arrays.copyOf(array, array.length * 2);
         array[p++] = value.intValue();
      }
      return Arrays.copyOf(array, p);
   }
}