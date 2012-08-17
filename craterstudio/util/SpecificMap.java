/*
 * Created on 4-nov-2007
 */

package craterstudio.util;

import java.util.HashMap;
import java.util.Map;

public class SpecificMap
{
   private final Map<String, ? super Object> map;

   public SpecificMap()
   {
      this(new HashMap<String, Object>());
   }

   public SpecificMap(Map<String, ? super Object> map)
   {
      this.map = map;
   }

   //

   public void putInt(String key, int val)
   {
      map.put(key, new Integer(val));
   }

   public int getInt(String key)
   {
      Object obj = map.get(key);
      if (obj == null)
         throw new IllegalStateException("key not found: " + key);

      if (obj instanceof Integer)
         return ((Integer) obj).intValue();

      if (obj instanceof String)
      {
         try
         {
            return Integer.parseInt((String) obj);
         }
         catch (NumberFormatException exc)
         {
            throw new IllegalStateException("key not integer: " + key);
         }
      }

      throw new IllegalStateException("key not convertable to integer: " + key);
   }

   public int getInt(String key, int def)
   {
      Object obj = map.get(key);
      if (obj == null)
         return def;

      if (obj instanceof Integer)
         return ((Integer) obj).intValue();

      if (obj instanceof String)
      {
         try
         {
            return Integer.parseInt((String) obj);
         }
         catch (NumberFormatException exc)
         {
            return def;
         }
      }

      return def;
   }

   //

   public void putString(String key, String val)
   {
      map.put(key, val);
   }

   public String getString(String key)
   {
      return this.getString(key, null);
   }

   public String getString(String key, String def)
   {
      Object obj = map.get(key);
      if (obj == null)
         return def;

      if (obj instanceof String)
         return (String) obj;

      return def;
   }

   //

   public boolean equals(Object obj)
   {
      if (!(obj instanceof SpecificMap))
         return false;
      return this.map.equals(((SpecificMap) obj).map);
   }

   public String toString()
   {
      return this.map.toString();
   }
}
