/*
 * Created on 22 sep 2008
 */

package craterstudio.util;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class ReflectionUtil
{
   public static String toString(Field field)
   {
      return field.getDeclaringClass().getSimpleName() + "{" + field.getType().getSimpleName() + " " + field.getName() + "}";
   }

   //

   private static final Map<String, Method> method_cache = new HashMap<String, Method>();

   public static Method findMethod(Class< ? > clzz, String name) throws NoSuchMethodException
   {
      String key = clzz.getName() + "~" + name;
      synchronized (method_cache)
      {
         if (method_cache.containsKey(key))
         {
            Method method = method_cache.get(key);
            if (method != null)
               return method;
            throw new NoSuchMethodException();
         }
      }

      Class< ? > original = clzz;

      do
      {
         for (Method method : clzz.getDeclaredMethods())
         {
            if (method.getName().equals(name))
            {
               synchronized (method_cache)
               {
                  method_cache.put(key, method);
               }
               return method;
            }
         }
      }
      while ((clzz = clzz.getSuperclass()) != null);

      synchronized (method_cache)
      {
         method_cache.put(key, null);
      }

      throw new NoSuchMethodException("name: " + name + " in " + original.getName());
   }

   //

   private static final Map<String, Field> field_cache = new HashMap<String, Field>();

   public static Field findField(Object obj, String name) throws NoSuchFieldException
   {
      return ReflectionUtil.findField(obj.getClass(), name);
   }

   public static Field findField(Class< ? > clzz, String name) throws NoSuchFieldException
   {
      String key = clzz.getName() + "~" + name;
      synchronized (field_cache)
      {
         if (field_cache.containsKey(key))
         {
            Field field = field_cache.get(key);
            if (field != null)
               return field;
            throw new NoSuchFieldException();
         }
      }

      Class< ? > original = clzz;

      do
      {
         try
         {
            Field field = clzz.getDeclaredField(name);
            synchronized (field_cache)
            {
               field_cache.put(key, field);
            }
            return field;
         }
         catch (NoSuchFieldException exc)
         {
            clzz = clzz.getSuperclass();
         }
      }
      while (clzz != null);

      synchronized (field_cache)
      {
         field_cache.put(key, null);
      }

      throw new NoSuchFieldException("name: " + name + " in " + original.getName());
   }

   public static final <T> T newInstance(Class<T> clazz)
   {
      try
      {
         return clazz.newInstance();
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static final <T> T[] newArray(Class<T> clazz, int len)
   {
      return (T[]) Array.newInstance(clazz, len);
   }

   public static final void setFieldValue(Field field, Object target, Object param)
   {
      try
      {
         field.set(target, param);
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(toString(field) + "[" + target + "]" + " = " + param, exc);
      }
   }

   public static final <T> T getFieldValue(Field field, Object target)
   {
      try
      {
         return (T) field.get(target);
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(toString(field) + "[" + target + "]", exc);
      }
   }

   public static final <T> Class<T> forName(String classname)
   {
      try
      {
         return (Class<T>) Class.forName(classname);
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static <T> void copyInto(T src, T dst, Iterable<Field> fields)
   {
      if (src.getClass() != dst.getClass())
      {
         throw new IllegalStateException("class mismatch");
      }

      for (Field field : fields)
      {
         ReflectionUtil.setFieldValue(field, dst, ReflectionUtil.getFieldValue(field, src));
      }
   }
}
