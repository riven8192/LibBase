/*
 * Created on 29-jul-2007
 */

package craterstudio.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

import craterstudio.text.Text;

public class FunctionPointer
{
   public static final FunctionPointer forClass(String classAndMethod)
   {
      return create(null, classAndMethod, true);
   }

   public static final FunctionPointer forClass(Class< ? > clzz, String methodName)
   {
      return create(null, clzz.getName() + "." + methodName + "()", true);
   }

   public static final FunctionPointer forInstance(Object target, String methodName)
   {
      if (target == null)
         throw new NullPointerException();
      return create(target, target.getClass().getName() + "." + methodName + "()", false);
   }

   private static final FunctionPointer create(Object target, String classAndMethod, boolean requestStatic)
   {
      try
      {
         if (!classAndMethod.endsWith("()"))
            throw new IllegalStateException("method-name must with \"()\"");

         classAndMethod = Text.chopLast(classAndMethod, 2); // remove ()
         Class< ? > clazz = Class.forName(Text.beforeLast(classAndMethod, '.'));
         String methodName = Text.afterLast(classAndMethod, '.');
         Method method = null;

         Method[] methods = HighLevel.findDeclaredMethods(clazz, methodName);
         if (methods.length == 0)
            throw new IllegalStateException("No such method: " + methodName + " in " + clazz.getName());
         if (methods.length != 1)
         {
            String msg = "Multiple methods named: " + methodName + " in " + clazz.getName() + "\n";
            for (Method m : methods)
               msg += " - " + m.toString() + "\n";
            throw new IllegalStateException(msg);
         }
         method = methods[0];

         HighLevel.forceAccess(method);

         boolean foundStatic = Modifier.isStatic(method.getModifiers());
         if (foundStatic != requestStatic)
            throw new IllegalStateException("method.isStatic=" + foundStatic + " while requested " + (requestStatic ? "static" : "instance") + " method");

         return new FunctionPointer(target, method);
      }
      catch (Exception exc)
      {
         exc.printStackTrace();
         return null;
      }
   }

   public FunctionPointer(Object target, Method method)
   {
      this.target = target;
      this.method = method;
   }

   public final FunctionPointer forNewInstance(Object target)
   {
      return new FunctionPointer(target, this.method);
   }

   private final Object target;
   private final Method method;
   private Object[]     args;

   public FunctionPointer pass(int paramOffset, Object... args)
   {
      for (int i = 0; i < args.length; i++)
         this.passAt(args[i], paramOffset + i);
      return this;
   }

   public FunctionPointer pass(Object... args)
   {
      return this.pass(0, args);
   }

   public FunctionPointer passAt(Object arg, int index)
   {
      if (this.args == null)
         this.args = new Object[index + 1];
      else if (index >= this.args.length)
         this.args = ArrayUtil.growTo(this.args, index + 1);

      this.args[index] = arg;

      return this;
   }

   public Object call()
   {
      try
      {
         if (method.getExceptionTypes().length != 0)
            throw new FunctionPointerCallException("method is declared to throw Exceptions", null);

         this.parameterSanityCheck();

         return method.invoke(target, args);
      }
      catch (InvocationTargetException exc)
      {
         Throwable cause = exc.getCause();
         if (cause instanceof RuntimeException)
            throw (RuntimeException) cause;
         throw new FunctionPointerCallException(exc.getCause().getMessage(), exc.getCause());
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public Object callWary() throws Exception
   {
      try
      {
         this.parameterSanityCheck();

         return method.invoke(target, args);
      }
      catch (InvocationTargetException exc)
      {
         Throwable cause = exc.getCause();
         if (cause instanceof Exception)
            throw (Exception) cause;
         throw new FunctionPointerCallException(exc.getCause().getMessage(), exc.getCause());
      }
      catch (Exception exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   private final void parameterSanityCheck()
   {
      if (this.args == null)
      {
         if (method.getParameterTypes().length != 0)
         {
            throw new IllegalStateException("cannot invoke:\n" + method + "\nwithout arguments");
         }
      }
      else if (method.getParameterTypes().length != this.args.length)
      {
         throw new IllegalStateException("cannot invoke\n" + method + "\nwith arguments:\n" + Arrays.toString(this.args));
      }
   }

   public class FunctionPointerCallException extends RuntimeException
   {
      public FunctionPointerCallException(String msg, Throwable cause)
      {
         super(msg, cause);
      }
   }

   public Runnable getRunnableCall()
   {
      return new Runnable()
      {
         public void run()
         {
            FunctionPointer.this.call();
         }
      };
   }

   public Runnable getRunnableCallWary()
   {
      return new Runnable()
      {
         public void run()
         {
            try
            {
               FunctionPointer.this.callWary();
            }
            catch (Exception exc)
            {
               exc.printStackTrace();
            }
         }
      };
   }
}