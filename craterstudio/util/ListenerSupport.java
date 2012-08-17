/*
 * Created on 14-jul-2007
 */

package craterstudio.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.swing.SwingUtilities;

public class ListenerSupport<L>
{
   private final Class<L> interf;
   private final List<L>  listeners;
   private final Method   onlyMethod;

   public ListenerSupport(Class< ? > interf)
   {
      if (!interf.isInterface())
         throw new IllegalArgumentException("must be interface: " + interf.getName());

      this.interf = (Class<L>) interf;
      this.listeners = new ArrayList<L>();

      Method[] mthds = interf.getMethods();
      this.onlyMethod = (mthds.length == 1) ? mthds[0] : null;

   }

   public void addListener(L listener)
   {
      synchronized (listeners)
      {
         if (listeners.contains(listener))
            throw new IllegalArgumentException("already registered as listener");
         listeners.add(listener);
      }
   }

   public void removeListener(L listener)
   {
      synchronized (listeners)
      {
         if (!listeners.remove(listener))
            throw new IllegalArgumentException("not registered as listener");
      }
   }

   private final LinkedList<L>       pending       = new LinkedList<L>();
   private final LinkedList<Boolean> pendingAction = new LinkedList<Boolean>();

   public void addListenerLater(L listener)
   {
      synchronized (listeners)
      {
         pending.add(listener);
         pendingAction.add(Boolean.TRUE);
      }
   }

   public void removeListenerLater(L listener)
   {
      synchronized (listeners)
      {
         pending.add(listener);
         pendingAction.add(Boolean.FALSE);
      }
   }

   public final void fireOnEDT(final Object... args)
   {
      SwingUtilities.invokeLater(new Runnable()
      {
         public void run()
         {
            fire(args);
         }
      });
   }

   public final void fireByName(String methodName, Object... args)
   {
      for (Method method : interf.getMethods())
      {
         if (method.getName().equals(methodName))
         {
            this.fire(method, args);
            break;
         }
      }
   }

   public final void fireByNameOnEDT(final String methodName, final Object... args)
   {
      SwingUtilities.invokeLater(new Runnable()
      {
         public void run()
         {
            fireByName(methodName, args);
         }
      });
   }

   public final void fire(Object... args)
   {
      if (this.onlyMethod == null)
         throw new IllegalStateException("interface must have only one method");
      this.fire(this.onlyMethod, args);
   }

   private final void fire(Method method, Object[] args)
   {
      synchronized (listeners)
      {
         for (int i = 0; i < pending.size(); i++)
         {
            L listener = pending.get(i);
            Boolean action = pendingAction.get(i);

            if (action.booleanValue())
               this.addListener(listener);
            else
               this.removeListener(listener);
         }
         pending.clear();
         pendingAction.clear();

         //

         for (L listener : listeners)
         {
            try
            {
               method.invoke(listener, args);
            }
            catch (InvocationTargetException exc)
            {
               exc.getCause().printStackTrace();
            }
            catch (Exception exc)
            {
               exc.printStackTrace();
            }
         }
      }
   }
}
