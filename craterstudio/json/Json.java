/*
 * Created on 5 aug 2010
 */

package craterstudio.json;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import craterstudio.json.impl.JSONArray;
import craterstudio.json.impl.JSONException;
import craterstudio.json.impl.JSONObject;
import craterstudio.json.impl.JSONWriter;
import craterstudio.util.IteratorUtil;

public class Json
{
   public static String pack(Object[] array) throws JSONException
   {
      return packImpl(Arrays.asList(array), false);
   }

   public static String pack(Map<String, Object> map) throws JSONException
   {
      return packImpl(Arrays.asList(map), true);
   }

   public static String pack(List< ? > list) throws JSONException
   {
      return packImpl(list, false);
   }

   private static String packImpl(List< ? > list, boolean trimArraySyntax) throws JSONException
   {
      StringWriter sw = new StringWriter();
      JSONWriter json = new JSONWriter(sw);
      json.array();
      for (Object item : list)
         json.value(item);
      json.endArray();

      String result = sw.toString();
      if (trimArraySyntax)
         result = result.substring(1, result.length() - 1);
      return result;
   }

   //

   public static Map<String, Object> unpack(String json) throws JSONException
   {
      if (json == null)
         return new HashMap<String, Object>();
      return unpackObject(new JSONObject(json));
   }

   private static Map<String, Object> unpackObject(JSONObject obj) throws JSONException
   {
      Map<String, Object> mapping = new HashMap<String, Object>();

      for (Object key : IteratorUtil.foreach(obj.keys()))
      {
         Object got = obj.get((String) key);
         if (got instanceof JSONObject)
            got = unpackObject((JSONObject) got);
         else if (got instanceof JSONArray)
            got = unpackArray((JSONArray) got);
         mapping.put((String) key, got);
      }

      return mapping;
   }

   private static List<Object> unpackArray(JSONArray arr) throws JSONException
   {
      List<Object> list = new ArrayList<Object>();

      for (int i = 0; i < arr.length(); i++)
      {
         if (arr.get(i) instanceof JSONObject)
            list.add(unpackObject(arr.getJSONObject(i)));
         else if (arr.get(i) instanceof JSONArray)
            list.add(unpackArray(arr.getJSONArray(i)));
         else
            list.add(arr.get(i));
      }
      return list;
   }
}