using System.Linq;
using System.Web.Mvc;

namespace MVC5Client.Controllers
{
    public class BecnhmarkController : Controller
    {
        public ActionResult Json4K()
        {
            return Json(Enumerable.Repeat(new { Id = 1, Name = "Voldemort" }, 200), JsonRequestBehavior.AllowGet);
        }

        public ActionResult Json4KInBranch() => Json4K();

        [OutputCache(Duration = 10)]
        public ActionResult CachedJson4K() => Json4K();

        [OutputCache(Duration = 10)]
        public ActionResult CachedJson4KInBranch() => Json4K();

    }
}
