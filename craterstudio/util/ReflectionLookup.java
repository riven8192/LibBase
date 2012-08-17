/*
 * Created on 21 jul 2008
 */

package craterstudio.util;

import static craterstudio.text.Text.*;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import craterstudio.text.Text;

public class ReflectionLookup
{
   public static Method lookupMethod(String line)
   {
      line = Text.remove(line, ' ');

      String className = beforeLast(before(line, '('), '.');
      String methodName = afterLast(before(line, '('), '.');
      String types = between(line, '(', ')');
      Class< ? >[] paramTypes = null;

      if (types.length() != 0)
      {
         String[] typeNames = split(types, ',');
         paramTypes = new Class< ? >[typeNames.length];
         for (int i = 0; i < paramTypes.length; i++)
            paramTypes[i] = ReflectionLookup.lookupType(typeNames[i]);
      }

      Class< ? > clazz = ReflectionLookup.lookupType(className);

      try
      {
         return clazz.getMethod(methodName, paramTypes);
      }
      catch (NoSuchMethodException exc)
      {
         throw new IllegalArgumentException(exc);
      }
   }

   private static final Set<String>             packageNames       = new HashSet<String>();
   private static final Set<String>             nonExistingClasses = new HashSet<String>();
   private static final Map<String, Class< ? >> existingClasses    = new HashMap<String, Class< ? >>();

   static
   {
      registerPackage("java.lang");

      existingClasses.put("boolean", boolean.class);
      existingClasses.put("byte", byte.class);
      existingClasses.put("short", short.class);
      existingClasses.put("char", char.class);
      existingClasses.put("int", int.class);
      existingClasses.put("long", long.class);
      existingClasses.put("float", float.class);
      existingClasses.put("double", double.class);

      existingClasses.put("boolean[]", boolean[].class);
      existingClasses.put("byte[]", byte[].class);
      existingClasses.put("short[]", short[].class);
      existingClasses.put("char[]", char[].class);
      existingClasses.put("int[]", int[].class);
      existingClasses.put("long[]", long[].class);
      existingClasses.put("float[]", float[].class);
      existingClasses.put("double[]", double[].class);
      
      existingClasses.put("boolean[][]", boolean[][].class);
      existingClasses.put("byte[][]", byte[][].class);
      existingClasses.put("short[][]", short[][].class);
      existingClasses.put("char[][]", char[][].class);
      existingClasses.put("int[][]", int[][].class);
      existingClasses.put("long[][]", long[][].class);
      existingClasses.put("float[][]", float[][].class);
      existingClasses.put("double[][]", double[][].class);

      existingClasses.put("boolean[][[]", boolean[][][].class);
      existingClasses.put("byte[][][]", byte[][][].class);
      existingClasses.put("short[][][]", short[][][].class);
      existingClasses.put("char[][][]", char[][][].class);
      existingClasses.put("int[][][]", int[][][].class);
      existingClasses.put("long[][][]", long[][][].class);
      existingClasses.put("float[][][]", float[][][].class);
      existingClasses.put("double[][][]", double[][][].class);
      
      // veel gekker moet het niet worden
   }

   public static void registerPackage(String packageName)
   {
      packageNames.add(packageName);
   }

   public static Class< ? > lookupType(String className)
   {
      final String passedClassName = className;

      Class< ? > quicky = existingClasses.get(passedClassName);
      if (quicky != null)
         return quicky;

      String pre = "";
      String post = "";
      while (className.endsWith("[]"))
      {
         className = Text.chopLast(className, 2);

         if (pre.equals(""))
         {
            pre = "L";
            post = ";";
         }

         pre = "[" + pre;
      }

      try
      {
         Class< ? > found = Class.forName(pre + className + post);
         existingClasses.put(passedClassName, found);
         return found;
      }
      catch (ClassNotFoundException exc)
      {
         // was worth a try...
      }

      for (String packageName : packageNames)
      {
         String fullClassName = pre + packageName + "." + className + post;
         if (nonExistingClasses.contains(fullClassName))
            continue;

         try
         {
            Class< ? > found = Class.forName(fullClassName);
            existingClasses.put(passedClassName, found);
            return found;
         }
         catch (ClassNotFoundException exc)
         {
            nonExistingClasses.add(fullClassName);
         }
      }

      throw new IllegalArgumentException("Class not found in packages: " + passedClassName);
   }
}