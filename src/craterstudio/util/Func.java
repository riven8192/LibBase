/*
 * Created on 18 nov 2008
 */

package craterstudio.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.NoSuchElementException;

import craterstudio.data.tuples.Pair;
import craterstudio.util.concur.Future;

public class Func<T>
{
   public static <T> Func<T> createInstance(Object target, String methodName, Class<T> returnType)
   {
      for (Method mthd : target.getClass().getMethods())
      {
         if (mthd.getName().equals(methodName))
         {
            if (returnType != null)
               if (returnType != mthd.getReturnType())
                  throw new IllegalArgumentException("returntype mismatch: " + returnType + ", expected: " + mthd.getReturnType());

            return new Func<T>(target, mthd);
         }
      }

      throw new NoSuchElementException(methodName);
   }

   public static <T> Func<T> createStatic(Class< ? > clazz, String methodName, Class<T> returnType)
   {
      for (Method mthd : clazz.getMethods())
      {
         if (mthd.getName().equals(methodName))
         {
            if (returnType != null)
               if (returnType != mthd.getReturnType())
                  throw new IllegalArgumentException("returntype mismatch: " + returnType + ", expected: " + mthd.getReturnType());

            return new Func<T>(null, mthd);
         }
      }

      throw new NoSuchElementException(methodName);
   }

   public static Func< ? > create(Class< ? > interf, Object target)
   {
      return Func.create(interf, target, null);
   }

   public static <T> Func<T> create(Class< ? > interf, Object target, Class<T> returnType)
   {
      if (!interf.isInterface())
         throw new IllegalArgumentException("class must be interface: " + interf.getName());
      if (!interf.isInstance(target))
         throw new IllegalArgumentException("target must implement interface: " + target);

      Method[] mthds = interf.getMethods();
      if (mthds.length != 1)
         throw new IllegalArgumentException("interface must have 1 method");

      Method method = mthds[0];

      for (Method mthd : target.getClass().getMethods())
      {
         if (!method.getName().equals(mthd.getName()))
            continue;
         if (method.getReturnType() != mthd.getReturnType())
            continue;
         if (!Arrays.equals(method.getParameterTypes(), mthd.getParameterTypes()))
            continue;

         // only declaring class is allowed to be different

         if (returnType != null)
            if (returnType != mthd.getReturnType())
               throw new IllegalArgumentException("returntype mismatch: " + returnType + ", expected: " + mthd.getReturnType());

         return new Func<T>(target, mthd);
      }

      throw new IllegalStateException("could not init func");
   }

   private final Object target;
   private final Method mthd;

   private Func(Object target, Method mthd)
   {
      this.target = target;
      this.mthd = mthd;
   }

   public Pair<Runnable, Future<T>> callLater(final Object... args)
   {
      final Future<T> future = new Future<T>();

      Runnable task = new Runnable()
      {
         @Override
         public void run()
         {
            future.set(Func.this.call(args));
         }
      };

      return new Pair<Runnable, Future<T>>(task, future);
   }

   public Future<T> asyncCall(final Object... args)
   {
      Pair<Runnable, Future<T>> later = this.callLater(args);
      new Thread(later.first()).start();
      return later.second();
   }

   public T call(Object... args)
   {
      try
      {
         return (T) this.mthd.invoke(this.target, args);
      }
      catch (InvocationTargetException exc)
      {
         throw new IllegalStateException(exc.getCause());
      }
      catch (IllegalAccessException exc)
      {
         throw new IllegalStateException("seriously fucked up access", exc);
      }
      catch (IllegalArgumentException exc)
      {
         Class< ? >[] argTypes = new Class[args.length];
         for (int i = 0; i < args.length; i++)
            argTypes[i] = (args[i] == null ? null : args[i].getClass());

         String msg = exc.getMessage() + "\n";
         msg += "    - target class:    " + this.target.getClass().getName() + "\n";
         msg += "    - target string:   " + this.target.toString() + "\n";
         msg += "    - signature:       " + this.mthd.toString() + "\n";
         msg += "    - argument values: " + Arrays.toString(args) + "\n";
         msg += "    - argument types:  " + Arrays.toString(argTypes);

         throw new IllegalArgumentException(msg);
      }
   }
}
