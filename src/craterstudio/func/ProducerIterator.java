/*
 * Created on 29 jun 2010
 */

package craterstudio.func;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class ProducerIterator<T> implements Iterable<T>
{
   final Producer<T> producer;

   public ProducerIterator(Producer<T> producer)
   {
      this.producer = producer;
   }

   @Override
   public Iterator<T> iterator()
   {
      return new Iterator<T>()
      {
         private T next = null;

         @Override
         public boolean hasNext()
         {
            if (this.next == Producer.NO_RESULT)
               return false;
            if (this.next != null)
               return true;
            this.next = producer.produce();
            if (this.next == Producer.NO_RESULT)
               return false;
            return (this.next != null);
         }

         @Override
         public T next()
         {
            if (this.next == Producer.NO_RESULT)
               throw new NoSuchElementException();
            if (this.next == null)
            {
               this.next = producer.produce();
               if (this.next == Producer.NO_RESULT)
                  throw new NoSuchElementException();
            }
            T result = this.next;
            this.next = null;
            return result;
         }

         @Override
         public void remove()
         {
            throw new UnsupportedOperationException();
         }
      };
   }
}
