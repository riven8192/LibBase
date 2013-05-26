/*
 * Created on 3 feb 2009
 */

package craterstudio.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SetUtil {
   public static <T> Set<T> create(T... items) {
      Set<T> set = new HashSet<T>();
      for (T item : items)
         set.add(item);
      return set;
   }
   
   public static <T> T[] toArray(Class<T> clazz, Set<T> set){
      return set.toArray((T[])Array.newInstance(clazz, set.size()));
   }
   
   //
   
   public static <T> Set<T> and(Set<T> a, Set<T> b) {
      Set<T> c = SetUtil.or(a, b);
      c.removeAll(SetUtil.xor(a, b));
      return c;
   }
   
   public static <T> Set<T> or(Set<T> a, Set<T> b) {
      Set<T> c = new HashSet<T>(a);
      c.addAll(b);
      return c;
   }
   
   public static <T> Set<T> xor(Set<T> a, Set<T> b) {
      Set<T> a_minus_b = new HashSet<T>(a);
      a_minus_b.removeAll(b);
      
      Set<T> b_minus_a = new HashSet<T>(b);
      b_minus_a.removeAll(a);
      
      Set<T> c = new HashSet<T>();
      c.addAll(a_minus_b);
      c.addAll(b_minus_a);
      return c;
   }
   
   public static <T> List<T> sort(Collection<T> set, Comparator<T> comp) {
      List<T> list = new ArrayList<T>();
      list.addAll(set);
      Collections.sort(list, comp);
      return list;
   }
}
