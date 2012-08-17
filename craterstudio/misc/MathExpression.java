package craterstudio.misc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/*
 * Created on 8-okt-2007
 */

public class MathExpression
{
   public static void main(String[] args) throws Exception
   {
      MathExpression expr = new MathExpression();
      expr.put("a", 3.0);
      expr.put("b", 4.0);
      expr.put("c", 5.0);

      //

      String in = ".31/(c+3.1415 * a)";
      System.out.println("input=" + in);

      System.out.println();

      //

      double out1 = expr.solve("d=" + in);
      double out2 = expr.solve("d=d+1.1");

      System.out.println("out1=" + out1);
      System.out.println("out2=" + out2);
   }

   private final Map<String, Double> vars;

   public MathExpression()
   {
      this.vars = new HashMap<String, Double>();
   }

   public double solve(String expr)
   {
      return this.parse(expr).solve();
   }

   public double put(String var, double value)
   {
      double current = Double.NaN;
      Double found = this.vars.remove(var);
      if (found != null)
         current = found.doubleValue();
      this.vars.put(var, Double.valueOf(value));
      return current;
   }

   public double get(String var)
   {
      Double value = this.vars.get(var);
      if (value == null)
         throw new NoSuchElementException("no such variable: " + var);
      return value.doubleValue();
   }

   public double remove(String var)
   {
      Double value = this.vars.remove(var);
      if (value == null)
         throw new NoSuchElementException("no such variable: " + var);
      return value.doubleValue();
   }

   // stuff

   private Node parse(String input)
   {
      CodeFeeder feeder = new CodeFeeder(this.vars);
      for (int i = 0; i < input.length(); i++)
         feeder.feed(input.charAt(i));
      feeder.finish();

      int[][] operatorOrder = new int[3][];
      operatorOrder[0] = new int[] { Operator.MULTIPLY, Operator.DIVIDE };
      operatorOrder[1] = new int[] { Operator.ADD, Operator.SUBTRACT };
      operatorOrder[2] = new int[] { Operator.ASSIGN };
      modifyByMathRules(feeder.node, operatorOrder);

      return feeder.node;
   }

   static boolean in_array(int find, int[] set)
   {
      for (int i = 0; i < set.length; i++)
         if (set[i] == find)
            return true;
      return false;
   }

   static void modifyByMathRules(Node node, int[][] operatorsPerLevel)
   {
      int[] levels = new int[operatorsPerLevel.length];
      int operatorCount = 0;
      for (int i = 0; i < node.elements.size(); i++)
      {
         Element element = node.elements.get(i);
         if (!(element instanceof Operator))
            continue;

         for (int k = 0; k < levels.length; k++)
            if (in_array(((Operator) element).code, operatorsPerLevel[k]))
               levels[k]++;
         operatorCount++;
      }

      boolean needsChange = false;
      for (int i = 0; i < levels.length; i++)
         if (levels[i] != 0 && levels[i] != operatorCount)
            needsChange = true;

      for (int k = 0; k < operatorsPerLevel.length && needsChange; k++)
      {
         boolean active = false;
         int startIndex = -1;

         for (int i = 0; i < node.elements.size(); i++)
         {
            Element element = node.elements.get(i);
            if (!(element instanceof Operator))
               continue;

            Operator op = (Operator) element;

            if (!active)
            {
               if (in_array(op.code, operatorsPerLevel[k]))
               {
                  active = true;
                  startIndex = i - 1;
               }
            }
            else
            {
               if (in_array(op.code, operatorsPerLevel[k]))
                  continue;

               active = false;

               Node sub = new Node();
               sub.parent = node;
               for (int m = i - 1; m >= startIndex; m--)
                  sub.elements.add(0, node.elements.remove(m));
               node.elements.add(startIndex, sub);

               i -= (sub.elements.size() - 1);
            }
         }

         if (active)
         {
            Node sub = new Node();
            sub.parent = node;
            for (int m = node.elements.size() - 1; m >= startIndex; m--)
               sub.elements.add(0, node.elements.remove(m));
            node.elements.add(startIndex, sub);
         }
      }

      for (int i = 0; i < node.elements.size(); i++)
         if (node.elements.get(i) instanceof Node)
            modifyByMathRules((Node) node.elements.get(i), operatorsPerLevel);
   }

   static class CodeFeeder
   {
      final Map<String, Double> mapping;
      Node                      node;

      public CodeFeeder(Map<String, Double> mapping)
      {
         this.mapping = mapping;
         node = new Node();
         node.ci = new VariableOrValueInterpreter(this, this.mapping);
      }

      public void feed(char c)
      {
         switch (c)
         {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
               return;

            case '(':
               Node next = new Node();
               next.parent = node;
               next.ci = new VariableOrValueInterpreter(this, this.mapping);
               node.elements.add(next);
               node = next;
               return;

            case ')':
               node.ci.finish();
               node = node.parent;
               return;
         }

         CodeInterpreter cur = node.ci;
         CodeInterpreter nxt = cur.feed(c);

         if (nxt != null)
         {
            node.ci = nxt;
            node.ci.feed(c);
         }
      }

      public void finish()
      {
         if (node.parent != null)
            throw new IllegalStateException("unexpected expression termination");
         node.ci.finish();
      }

   }

   static abstract class CodeInterpreter
   {
      CodeFeeder feeder;

      CodeInterpreter(CodeFeeder feeder)
      {
         this.feeder = feeder;
      }

      abstract CodeInterpreter feed(char c);

      abstract void finish();
   }

   static class VariableOrValueInterpreter extends CodeInterpreter
   {
      private final Map<String, Double> mapping;

      public VariableOrValueInterpreter(CodeFeeder feeder, Map<String, Double> mapping)
      {
         super(feeder);
         this.mapping = mapping;
      }

      char[] name  = new char[1024];
      int    index = 0;

      CodeInterpreter feed(char c)
      {
         if (!is(c))
         {
            feeder.node.elements.add(this.createVariableOrValue(String.valueOf(name, 0, index)));
            index = 0;
            return new OperatorInterpreter(feeder, this.mapping);
         }

         name[index++] = c;

         return null;
      }

      public void finish()
      {
         if (index == 0)
            return;
         feeder.node.elements.add(this.createVariableOrValue(String.valueOf(name, 0, index)));
         index = 0;
      }

      private Element createVariableOrValue(String str)
      {
         if (this.isBuildingValue)
            return new Value(Double.parseDouble(str));
         return new Variable(this.mapping, str);
      }

      boolean isBuildingValue;
      int     periodCount = 0;

      boolean is(char c)
      {
         if (index == 0)
         {
            this.isBuildingValue = (c >= '0' && c <= '9') || (c == '.');
            this.periodCount = 0;
         }

         if (c >= '0' && c <= '9')
            return true;

         if (false || //
               (c >= 'a' && c <= 'z') || //
               (c >= 'A' && c <= 'Z') || //
               (c == '_' || c == '$'))
         {
            if (index != 0 && this.isBuildingValue)
               throw new IllegalArgumentException("character in value: " + c);
            return true;
         }

         if (this.isBuildingValue)
         {
            if (c == '.')
            {
               if (++this.periodCount == 1)
                  return true;
               throw new IllegalArgumentException("more than 1 period in value");
            }
         }

         return false;
      }
   }

   static class Node extends Element
   {
      Node            parent;
      List<Element>   elements = new ArrayList<Element>();
      CodeInterpreter ci;

      @Override
      public double solve()
      {
         Element operand_1 = null;
         Element operand_2 = null;
         Operator nextOp = null;

         boolean mustBeOperation = false;
         for (Element element : this.elements)
         {
            if (mustBeOperation != ((element instanceof Operator)))
            {
               throw new IllegalStateException();
            }

            if (mustBeOperation)
            {
               nextOp = (Operator) element;
            }
            else
            {
               Element current;

               if (element instanceof Node)
               {
                  Node nod = (Node) element;
                  current = new Value(nod.solve());
               }
               else if (element instanceof Variable)
               {
                  Variable var = (Variable) element;
                  current = var;
               }
               else if (element instanceof Value)
               {
                  Value val = (Value) element;
                  current = val;
               }
               else
               {
                  throw new IllegalStateException();
               }

               operand_2 = operand_1;
               operand_1 = current;

               if (nextOp != null)
               {
                  double result = nextOp.solve(operand_1, operand_2);
                  operand_1 = new Value(result);
               }
            }

            mustBeOperation = !mustBeOperation;
         }

         if (!mustBeOperation)
            throw new IllegalStateException("operator was found at end of expression");

         return operand_1.solve();
      }
   }

   static class OperatorInterpreter extends CodeInterpreter
   {
      private final Map<String, Double> mapping;

      public OperatorInterpreter(CodeFeeder feeder, Map<String, Double> mapping)
      {
         super(feeder);
         this.mapping = mapping;
      }

      CodeInterpreter feed(char c)
      {
         Operator op = Operator.create((byte) c);
         if (op == null)
            return new VariableOrValueInterpreter(feeder, this.mapping);

         feeder.node.elements.add(op);

         return null;
      }

      public void finish()
      {
         //
      }
   }

   static abstract class Element
   {
      public abstract double solve();
   }

   static class Value extends Element
   {
      public final double value;

      public Value(double value)
      {
         this.value = value;
      }

      @Override
      public double solve()
      {
         return this.value;
      }

      @Override
      public String toString()
      {
         return String.valueOf(this.value);
      }
   }

   static class Variable extends Element
   {
      public final Map<String, Double> mapping;
      public final String              name;

      public Variable(Map<String, Double> mapping, String name)
      {
         if (mapping == null)
            throw new IllegalArgumentException("cannot create variable \"" + name + "\" without mapping");
         if (name.equals(""))
            throw new IllegalArgumentException("variable without name");

         this.mapping = mapping;
         this.name = name;
      }

      public void assign(double value)
      {
         this.mapping.put(this.name, Double.valueOf(value));
      }

      @Override
      public double solve()
      {
         Double value = this.mapping.get(this.name);
         if (value == null)
            throw new NoSuchElementException(this.name);
         return value.doubleValue();
      }

      public String toString()
      {
         return name;
      }
   }

   static class Operator extends Element
   {
      public final int code;

      public Operator(int code)
      {
         this.code = code;
      }

      @Override
      public double solve()
      {
         throw new IllegalStateException();
      }

      public double solve(Element operand_1, Element operand_2)
      {
         double op1 = operand_1.solve();

         if (this.code == ASSIGN)
         {
            if (operand_2 instanceof Variable)
            {
               ((Variable) operand_2).assign(op1);
               return op1;
            }
            throw new IllegalStateException("can only assign value to variable");
         }

         double op2 = operand_2.solve();

         switch (this.code)
         {
            case ADD:
               return op2 + op1;
            case SUBTRACT:
               return op2 - op1;
            case MULTIPLY:
               return op2 * op1;
            case DIVIDE:
               return op2 / op1;
            case MODULO:
               return op2 % op1;
            case POWER:
               return Math.pow(op2, op1);

            default:
               throw new IllegalStateException();
         }
      }

      public String toString()
      {
         switch (code)
         {
            case ASSIGN:
               return "=";
            case ADD:
               return "+";
            case SUBTRACT:
               return "-";
            case MULTIPLY:
               return "*";
            case DIVIDE:
               return "/";
            case MODULO:
               return "%";
            case POWER:
               return "^";
            default:
               return null;
         }
      }

      public static final int ASSIGN   = 0;
      public static final int ADD      = 1 << 0;
      public static final int SUBTRACT = 1 << 1;
      public static final int MULTIPLY = 1 << 2;
      public static final int DIVIDE   = 1 << 3;
      public static final int MODULO   = 1 << 4;
      public static final int POWER    = 1 << 5;

      public static Operator create(byte b)
      {
         switch (b)
         {
            case '=':
               return new Operator(ASSIGN);
            case '+':
               return new Operator(ADD);
            case '-':
               return new Operator(SUBTRACT);
            case '*':
               return new Operator(MULTIPLY);
            case '/':
               return new Operator(DIVIDE);
            case '%':
               return new Operator(MODULO);
            case '^':
               return new Operator(POWER);
            default:
               return null;
         }
      }
   }
}
