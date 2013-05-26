/*
 * Created on 24 mrt 2011
 */

package craterstudio.func;

import java.util.ArrayList;
import java.util.List;

import craterstudio.text.Text;
import craterstudio.text.TextValues;
import craterstudio.util.Asserts;

public class Filters
{
   public static final <T> Filter<T> createAndFilter(final List<Filter<T>> filters)
   {
      Asserts.assertNotNull(filters);

      return new Filter<T>()
      {
         public boolean accept(T item)
         {
            for (Filter<T> filter : filters)
               if (!filter.accept(item))
                  return false;
            return true;
         }

         @Override
         public String toString()
         {
            return "AND-filters[" + filters + "]";
         }
      };
   }

   public static final <T> Filter<T> createOrFilter(final List<Filter<T>> filters)
   {
      Asserts.assertNotNull(filters);

      return new Filter<T>()
      {
         public boolean accept(T item)
         {
            for (Filter<T> filter : filters)
               if (filter.accept(item))
                  return true;
            return false;
         }

         @Override
         public String toString()
         {
            return "OR-filters[" + filters + "]";
         }
      };
   }

   // -- int filters

   public static Filter<Boolean> createBooleanFromEval(String eval)
   {
      if ((eval = eval.trim()).isEmpty())
         return null;

      boolean expect = false;

      if (eval.equals("true") || eval.equals("1") || eval.equals("x") || eval.equals("v"))
         expect = true;
      else if (eval.equals("false") || eval.equals("0") || eval.equals("."))
         expect = false;
      else
         return null;

      final boolean match = expect;

      return new Filter<Boolean>()
      {
         @Override
         public boolean accept(Boolean item)
         {
            return item.booleanValue() == match;
         }
      };
   }

   private static <T extends Comparable<T>> List<Filter<T>> splitEval(String eval, String split, Transformer<String, T> compiler)
   {
      String[] parts = Text.split(eval, split);
      if (parts.length == 1) // no matches
         return null;

      List<Filter<T>> filters = new ArrayList<Filter<T>>();
      for (String part : parts)
      {
         Filter<T> filter = createCompareFilterFromEval(part, compiler);
         if (filter == null)
            continue;
         filters.add(filter);
      }
      if (filters.isEmpty())
         return null;

      return filters;
   }

   private static List<Filter<Integer>> splitIntEval(String eval, String split)
   {
      String[] parts = Text.split(eval, split);
      if (parts.length == 1) // no matches
         return null;

      List<Filter<Integer>> filters = new ArrayList<Filter<Integer>>();
      for (String part : parts)
      {
         Filter<Integer> filter = createIntFromEval(part);
         if (filter == null)
            continue;
         filters.add(filter);
      }
      if (filters.isEmpty())
         return null;

      return filters;
   }

   private static <T extends Comparable<T>> Filter<T> evalSplit(String eval, Transformer<String, T> compiler)
   {
      if ((eval = eval.trim()).isEmpty())
         return null;

      // OR
      {
         List<Filter<T>> list;

         list = splitEval(eval, "|", compiler);
         if (list != null)
            return createOrFilter(list);

         list = splitEval(eval, ",", compiler);
         if (list != null)
            return createOrFilter(list);
      }

      // AND
      {
         List<Filter<T>> list;

         list = splitEval(eval, "&", compiler);
         if (list != null)
            return createAndFilter(list);
      }

      return null;
   }

   public static Filter<Integer> createIntFromEval(String eval)
   {
      // OR
      {
         List<Filter<Integer>> list;

         list = splitIntEval(eval, "|");
         if (list != null)
            return createOrFilter(list);

         list = splitIntEval(eval, ",");
         if (list != null)
            return createOrFilter(list);
      }

      // AND
      {
         List<Filter<Integer>> list;

         list = splitIntEval(eval, "&");
         if (list != null)
            return createAndFilter(list);
      }

      if ((eval = eval.trim()).isEmpty())
         return null;

      // support ranges
      {
         if (eval.contains(".."))
         {
            try
            {
               String[] pair = Text.splitPair(eval, "..");
               for (int i = 0; i < pair.length; i++)
                  pair[i] = pair[i].trim();
               int[] minmax = TextValues.parseInts(pair);
               return createIntInRange(minmax[0], minmax[1], true);
            }
            catch (Exception exc)
            {
               return null;
            }
         }
         if (eval.indexOf("-", 1) != -1)
         {
            try
            {
               // UGLY HACK FOR NEGATIVE NUMBERS!
               String[] pair = Text.splitPair(eval.substring(1), "-");
               pair[0] = eval.substring(0, 1) + pair[0];

               for (int i = 0; i < pair.length; i++)
                  pair[i] = pair[i].trim();
               int[] minmax = TextValues.parseInts(pair);
               return createIntInRange(minmax[0], minmax[1], true);
            }
            catch (Exception exc)
            {
               return null;
            }
         }
      }

      for (String cmd : new String[] { "==", "!=", "<>", ">=", "<=", ">", "<", "=", "!", "" /* means: only a number */}) // order: long to short
      {
         if (!eval.startsWith(cmd))
            continue;

         String num = eval.substring(cmd.length()).trim();
         int val = TextValues.tryParseInt(num, Integer.MIN_VALUE);
         if (val == Integer.MIN_VALUE)
            return null;
         if (cmd.isEmpty())
            cmd = "=";
         return createIntCompare(val, cmd);
      }

      return null;
   }

   public static Filter<Integer> createIntInRange(final int min, final int max, boolean maxInclusive)
   {
      Asserts.assertLessOrEqual(min, max);

      if (maxInclusive)
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               int val = item.intValue();
               return min <= val && val <= max;
            }
         };

      return new Filter<Integer>()
      {
         @Override
         public boolean accept(Integer item)
         {
            int val = item.intValue();
            return min <= val && val < max;
         }
      };
   }

   public static Filter<Integer> createIntCompare(final int value, String operator)
   {
      if (operator.equals("==") || operator.equals("=") || operator.equals(""))
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               return item.intValue() == value;
            }
         };

      if (operator.equals("!=") || operator.equals("<>") || operator.equals("!"))
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               return item.intValue() != value;
            }
         };

      if (operator.equals("<"))
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               return item.intValue() < value;
            }
         };

      if (operator.equals("<="))
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               return item.intValue() <= value;
            }
         };

      if (operator.equals(">"))
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               return item.intValue() > value;
            }
         };

      if (operator.equals(">="))
         return new Filter<Integer>()
         {
            @Override
            public boolean accept(Integer item)
            {
               return item.intValue() >= value;
            }
         };

      throw new IllegalArgumentException("unknown compare type: '" + operator + "'");
   }

   private static final String[] operators = new String[] { "==", "!=", "<>", ">=", "<=", ">", "<", "=", "!" /* means: only a number */}; // order: long to short

   public static <T extends Comparable<T>> Filter<T> createCompareFilterFromEval(String eval, Transformer<String, T> compiler)
   {
      Filter<T> f = evalSplit(eval, compiler);
      if (f != null)
         return f;

      for (String operator : operators)
      {
         if (!eval.startsWith(operator))
            continue;

         String num = eval.substring(operator.length()).trim();
         T value = compiler.transform(num);
         return createCompareFilter(value, operator);
      }

      return null;
   }

   public static <T extends Comparable<T>> Filter<T> createCompareFilter(final T value, final String operator)
   {
      final Filter<Integer> backing = createIntCompare(0, operator);

      return new Filter<T>()
      {
         @Override
         public boolean accept(T item)
         {
            return backing.accept(Integer.valueOf(Integer.signum(item.compareTo(value))));
         }

         @Override
         public String toString()
         {
            return "filter['" + operator + "', '" + value + "']";
         }
      };
   }

   // -- string filters

   public static Filter<String> createNotEmptyFilter(boolean trim)
   {
      return new TrimNotEmptyFilter(trim);
   }

   public static Filter<String> createStartsWithCaseInsensitiveFilter(String find)
   {
      return new StartsWithCaseInsensitiveFilter(find);
   }

   public static Filter<String> createContainsCaseInsensitiveFilter(String find)
   {
      return new ContainsCaseInsensitiveFilter(find);
   }

   //

   private static class TrimNotEmptyFilter implements Filter<String>
   {
      private final boolean trim;

      public TrimNotEmptyFilter(boolean trim)
      {
         this.trim = trim;
      }

      public boolean accept(String value)
      {
         if (value == null)
            return false;
         if (this.trim)
            value = value.trim();
         return !value.isEmpty();
      }
   }

   private static class StartsWithCaseInsensitiveFilter implements Filter<String>
   {
      private final String find;

      public StartsWithCaseInsensitiveFilter(String find)
      {
         this.find = find.toLowerCase();
      }

      @Override
      public boolean accept(String item)
      {
         if (item.length() < find.length())
            return false;
         String begin = item.substring(0, find.length());
         return begin.toLowerCase().equals(find);
      }
   }

   private static class ContainsCaseInsensitiveFilter implements Filter<String>
   {
      private final String find;

      public ContainsCaseInsensitiveFilter(String find)
      {
         this.find = find.toLowerCase();
      }

      @Override
      public boolean accept(String item)
      {
         if (item.length() < find.length())
            return false;
         return item.toLowerCase().contains(find);
      }
   }
}
