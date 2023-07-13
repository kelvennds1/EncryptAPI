using Microsoft.AspNetCore.Mvc;
using Sinqia4Devs.Utils.Cryptography;

namespace EncryptAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EncryptRSAController : ControllerBase
    {
        [HttpPost]
        public IActionResult Encrypt([FromHeader(Name = "publicKey")] string publicKey, [FromHeader] string parametroPath)
        {

            string XSINQIARequest = Rsa.Encrypt(parametroPath, publicKey);

            return Ok(XSINQIARequest);
        }
    }
}
    