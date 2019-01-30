using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using Nancy;
using Nancy.Responses;

namespace CsClientApp
{
    public class CalcNancyModule : NancyModule
    {
        public CalcNancyModule()
        {
            After.AddItemToEndOfPipeline((ctx) => ctx.Response
                 .WithHeader("Access-Control-Allow-Origin", GetOrigin(ctx))
                 .WithHeader("Access-Control-Allow-Methods", "POST,GET")
                 .WithHeader("Access-Control-Allow-Headers", "Accept, Origin, Content-type"));

            Get["/Calc"] = _ =>
            {
                //Simaulate hard work...
                Thread.Sleep(1000);

                var assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
                return $"{{ \"version\": \"{assemblyVersion}\" }}";
            };
            Get["/Calc/Add"] = _ =>
            {
                //Simaulate hard work...
                Thread.Sleep(1000);

                var num1String = Request.Query["num1"] ?? "";
                var num2String = Request.Query["num2"] ?? "";

                var parsed1 = int.TryParse(num1String, out int num1);
                var parsed2 = int.TryParse(num2String, out int num2);
                var parsed = parsed1 && parsed2;

                if (parsed)
                    return $"{{ \"result\": \"{num1 + num2}\" }}";
                else
                    return $"{{ \"error\": \"can't parse input values\" }}";
            };
        }

        private string GetOrigin(NancyContext ctx)
        {
            return ctx.Request?.Headers["Origin"]?.FirstOrDefault() ?? "";
        }
    }
}
