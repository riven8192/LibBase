/*
 * Created on Sep 7, 2004
 */
package craterstudio.text;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TextWildcardSearch
{
   public static String format(String input, String pattern, String format)
   {
      String[][] matches = retreiveMatches(input, pattern);

      if (matches == null)
         return null;
      if (matches.length != 1)
         throw new IllegalStateException("ambigious convert: multiple matches");

      String[] match = matches[0];

      if (format.indexOf('*') != -1)
      {
         // "abc*def*ghi{0}" ==> "abc{0}def{1}ghi{2}{0}"

         int counter = 0;
         StringBuilder sb = new StringBuilder();
         for (int i = 0; i < format.length(); i++)
         {
            if (format.charAt(i) == '*')
               sb.append('{').append(counter++).append('}');
            else
               sb.append(format.charAt(i));
         }
         format = sb.toString();
      }

      String[] parts = Text.multiSplitAll(format, '{', '}');

      boolean odd = pattern.startsWith("*");
      for (int i = 1; i < parts.length; i += 2)
         parts[i] = match[(odd ? 0 : 1) + Integer.parseInt(parts[i]) * 2];
      return Text.join(parts);
   }

   public static boolean matches(String input, String pattern)
   {
      return countMatches(input, pattern) > 0;
   }

   public static int countMatches(String input, String pattern)
   {
      return ((Integer) matchesImpl(input, pattern, false)).intValue();
   }

   public static String[] retreiveFirstMatch(String input, String pattern)
   {
      String[][] result = retreiveMatches(input, pattern);
      return (result == null) ? null : result[0];
   }

   public static String[][] retreiveMatches(String input, String pattern)
   {
      return (String[][]) matchesImpl(input, pattern, true);
   }

   // impl

   private static Object matchesImpl(String input, String pattern, boolean returnResults)
   {
      if (pattern.length() == 0)
      {
         return null;
      }

      if (pattern.contains("**"))
      {
         throw new IllegalStateException();
      }

      // shortcuts
      shortcuts: if (Text.count(pattern, '*') <= 2)
      {
         int i_a = pattern.indexOf('*');
         int i_b = pattern.lastIndexOf('*');

         if (i_a == i_b) // abcxyz, abc*, *xyz, abc*xyz
         {
            return matchShortcuts(input, pattern, i_a, returnResults);
         }

         if (i_a != 0 || i_b != pattern.length() - 1) // *xyz*
            break shortcuts;

         String find = pattern.substring(1, pattern.length() - 1);
         String inner = input.substring(1, input.length() - 1);

         if (!inner.contains(find))
            return returnResults ? null : Integer.valueOf(0);

         if (!returnResults)
            return Integer.valueOf(Text.count(inner, find) - 1);

         String[] parts = Text.split(inner, find);
         String[][] result = new String[parts.length - 1][];
         for (int i = 0; i < result.length; i++)
         {
            String a = Text.join(parts, 0, i + 1, find);
            String b = Text.join(parts, i + 1, parts.length - 1 - i, find);
            result[i] = new String[] { input.charAt(0) + a, find, b + input.charAt(input.length() - 1) };
         }
         return result;
      }

      // crunch some numbers!

      String[] parts = Text.split(pattern, '*');
      int[] len = new int[parts.length];
      for (int i = 0; i < len.length; i++)
         len[i] = parts[i].length();

      int[][] perm = new int[parts.length][];
      for (int i = 0; i < parts.length; i++)
      {
         if (i == 0 && parts[i].length() == 0) // first is empty
            perm[i] = new int[] { 0 };
         else if (i == parts.length - 1 && parts[i].length() == 0) // last is empty
            perm[i] = new int[] { input.length() };
         else
            perm[i] = Text.indicesOf(input, parts[i]);
      }
      perm = createAllPermutations(perm);
      perm = filterNonIncreasingSequences(perm);
      perm = filterNonFittingSequences(perm, len, input.length());

      if (!returnResults)
      {
         return Integer.valueOf(perm.length);
      }

      if (perm.length == 0)
      {
         return null;
      }

      boolean initialGuess = pattern.charAt(0) == '*';
      boolean trailingGuess = pattern.charAt(pattern.length() - 1) == '*';

      int seq = (perm[0].length - 1) * 2 + 1;
      if (initialGuess)
         seq -= 1;
      if (trailingGuess)
         seq -= 1;

      String[][] results = new String[perm.length][seq];

      for (int i = 0, c = 0; i < perm.length; i++, c = 0)
      {
         if (!initialGuess)
         {
            results[i][c++] = input.substring(perm[i][0], perm[i][0] + len[0]);
         }

         for (int k = 1; k < perm[i].length; k++)
         {
            {
               results[i][c++] = input.substring(perm[i][k - 1] + 1 * len[k - 1], perm[i][k] + 0 * len[k]);
            }

            if (k != perm[i].length - 1 || !trailingGuess)
            {
               results[i][c++] = input.substring(perm[i][k - 0] + 0 * len[k - 0], perm[i][k] + 1 * len[k]);
            }
         }
      }

      return results;
   }

   private static Object matchShortcuts(String input, String pattern, int indexOf, boolean returnResults)
   {
      if (indexOf == -1) // "xyz" ==> equals
      {
         boolean b = input.equals(pattern);
         if (returnResults)
            return b ? new String[][] { { input } } : null;
         return Integer.valueOf(b ? 1 : 0);
      }

      if (indexOf == 0) // "*xyz" ==> endsWith
      {
         if (pattern.length() == 1) // "*" ==> always matches
         {
            if (returnResults)
               return new String[][] { { input } };
            return Integer.valueOf(1);
         }
         String m = pattern.substring(1);
         boolean b = input.endsWith(m);
         if (returnResults)
            return b ? new String[][] { { input.substring(0, input.length() - m.length()), m } } : null;
         return Integer.valueOf(b ? 1 : 0);
      }

      if (indexOf == pattern.length() - 1) // "xyz*" ==> startsWith
      {
         String m = pattern.substring(0, pattern.length() - 1);
         boolean b = input.startsWith(m);
         if (returnResults)
            return b ? new String[][] { { m, input.substring(m.length()) } } : null;
         return Integer.valueOf(b ? 1 : 0);
      }

      // "abc*xyz"
      {
         String before = pattern.substring(0, indexOf);
         String after = pattern.substring(indexOf + 1);
         boolean b = ((before.length() + after.length() < input.length()) && input.startsWith(before) && input.endsWith(after));
         if (returnResults)
            return b ? new String[][] { { before, input.substring(before.length(), input.length() - after.length()), after } } : null;
         return Integer.valueOf(b ? 1 : 0);
      }
   }

   private static int[][] filterNonFittingSequences(int[][] table, int[] len, int end)
   {
      List<int[]> list = new ArrayList<int[]>();

      outer: for (int[] row : table)
      {
         if (row[0] != 0)
            continue;

         for (int i = 1; i < row.length; i++)
         {
            if (i == len.length - 1)
               if (end - row[len.length - 1] != len[len.length - 1])
                  continue outer;

            if (row[i] - row[i - 1] < len[i - 1])
               continue outer;
         }

         list.add(row);
      }

      int[][] holder = new int[list.size()][];
      for (int i = 0; i < holder.length; i++)
         holder[i] = list.get(i);
      return holder;
   }

   private static int[][] filterNonIncreasingSequences(int[][] table)
   {
      List<int[]> list = new ArrayList<int[]>();

      for (int i = 0; i < table.length; i++)
         if (isIncreasing(table[i]))
            list.add(table[i]);

      int[][] holder = new int[list.size()][];
      for (int i = 0; i < holder.length; i++)
         holder[i] = list.get(i);
      return holder;
   }

   private static boolean isIncreasing(int[] row)
   {
      for (int i = 1; i < row.length; i++)
         if (row[i] <= row[i - 1])
            return false;
      return true;
   }

   private static int[][] createAllPermutations(int[][] table)
   {
      List<int[]> list = new ArrayList<int[]>();

      int entries = 1;
      for (int[] ia : table)
         entries *= ia.length;

      for (int i = 0; i < entries; i++)
         list.add(createOnePerm(table, i));

      int[][] holder = new int[list.size()][];
      for (int i = 0; i < holder.length; i++)
         holder[i] = list.get(i);
      return holder;
   }

   private static int[] createOnePerm(int[][] table, int entry)
   {
      int[] x = new int[table.length];
      for (int i = 0; i < x.length; i++)
      {
         int[] val = table[i];
         x[i] = val[entry % val.length];
         entry /= val.length;
      }
      return x;
   }
}