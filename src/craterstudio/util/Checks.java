/*
 * Created on 22 mrt 2011
 */

package craterstudio.util;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collection;

public class Checks
{
   public static final <T> T notIn(T find, T[] arr)
   {
      return notIn(find, arr, "ERROR");
   }

   public static final <T> T in(T find, T[] arr)
   {
      return in(find, arr, "ERROR");
   }

   public static final <T> T notEmpty(T t)
   {
      return notEmpty(t, "ERROR");
   }

   public static final <T> T notNull(T t)
   {
      return notNull(t, "ERROR");
   }

   public static final <T> T notIn(T find, T[] arr, String msg)
   {
      for (T t : arr)
         if (t == find || (t != null && t.equals(find)))
            throw new IllegalStateException(msg + ": " + find + " IN " + Arrays.toString(arr));
      return find;
   }

   public static final <T> T in(T find, T[] arr, String msg)
   {
      for (T t : arr)
         if (t == find || (t != null && t.equals(find)))
            return t;
      throw new IllegalStateException(msg + ": " + find + " NOT IN " + Arrays.toString(arr));
   }

   public static final <T> T notEmpty(T t, String msg)
   {
      if (t == null)
         throw new IllegalStateException(msg + ": NULL EMPTY");

      if (t instanceof String)
      {
         if (((String) t).trim().length() == 0)
            throw new IllegalStateException(msg + ": " + t + " STRING EMPTY");
         return t;
      }

      if (t instanceof Collection< ? >)
      {
         if (((Collection< ? >) t).size() == 0)
            throw new IllegalStateException(msg + ": " + t + " COLLECTION EMPTY");
         return t;
      }

      if (t.getClass().isArray())
      {
         if (Array.getLength(t) == 0)
            throw new IllegalStateException(msg + ": " + t + " ARRAY EMPTY");
         return t;
      }

      if (t instanceof Number)
      {
         if ((t instanceof Byte) && ((Byte) t).byteValue() == 0)
            throw new IllegalArgumentException(msg + ": BYTE ZERO");
         if ((t instanceof Short) && ((Short) t).shortValue() == 0)
            throw new IllegalArgumentException(msg + ": SHORT ZERO");
         if ((t instanceof Character) && ((Character) t).charValue() <= ' ') // whitespace
            throw new IllegalArgumentException(msg + ": CHAR EMPTY");
         if ((t instanceof Integer) && ((Integer) t).intValue() == 0)
            throw new IllegalArgumentException(msg + ": INT ZERO");
         if ((t instanceof Long) && ((Long) t).longValue() == 0)
            throw new IllegalArgumentException(msg + ": LONG ZERO");
         if ((t instanceof Float) && ((Float) t).floatValue() == 0.0f)
            throw new IllegalArgumentException(msg + ": FLOAT ZERO");
         if ((t instanceof Double) && ((Double) t).doubleValue() == 0.0)
            throw new IllegalArgumentException(msg + ": DOUBLE ZERO");
         return t;
      }

      if (t instanceof Boolean)
      {
         if (((Boolean) t).booleanValue() == false)
            throw new IllegalArgumentException(msg + ": BOOLEAN ZERO");
         return t;
      }

      return t;
   }

   public static final <T> T notNull(T t, String msg)
   {
      if (t == null)
         throw new IllegalStateException(msg + ": WAS NULL");
      return t;
   }

   public static final boolean notFalse(boolean t, String msg)
   {
      if (!t)
         throw new IllegalStateException(msg + ": WAS FALSE");
      return t;
   }

   public static <T> int nullCount(T... arr)
   {
      int count = 0;
      for (T t : arr)
         if (t == null)
            count++;
      return count;
   }

}
